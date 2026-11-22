using System.Diagnostics;
using System.Text.RegularExpressions;
using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

/// <summary>
/// Real Windows Firewall per-application blocking and unblocking via netsh advfirewall.
/// Every rule created uses the explicit "BECETTI-BLOCK-" prefix so BECETTI SECURITY only
/// manages its own rules and never touches unrelated Windows Firewall policies.
/// </summary>
public interface IPerAppFirewallService
{
    Task<OperationResult<IReadOnlyList<FirewallBlockedApp>>> GetBlockedAppsAsync(CancellationToken ct = default);
    Task<OperationResult> BlockApplicationAsync(string executablePath, CancellationToken ct = default);
    Task<OperationResult> UnblockApplicationAsync(string ruleName, CancellationToken ct = default);
}

public sealed class PerAppFirewallService : IPerAppFirewallService
{
    private const string RulePrefix = "BECETTI-BLOCK-";

    public async Task<OperationResult<IReadOnlyList<FirewallBlockedApp>>> GetBlockedAppsAsync(CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
            return OperationResult<IReadOnlyList<FirewallBlockedApp>>.Fail("Windows Firewall management requires Windows.", "UNSUPPORTED_OS");

        var (exitCode, stdout, stderr) = await RunNetshAsync("advfirewall firewall show rule name=all verbose", ct).ConfigureAwait(false);
        if (exitCode != 0 && string.IsNullOrWhiteSpace(stdout))
            return OperationResult<IReadOnlyList<FirewallBlockedApp>>.Fail(
                $"Could not query Windows Firewall rules: {stderr}", "FIREWALL_QUERY_ERROR");

        var blocked = ParseBecettiRules(stdout);
        return OperationResult<IReadOnlyList<FirewallBlockedApp>>.Ok(blocked, $"{blocked.Count} BECETTI firewall block rule(s) active.");
    }

    public async Task<OperationResult> BlockApplicationAsync(string executablePath, CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
            return OperationResult.Fail("Windows Firewall management requires Windows.", "UNSUPPORTED_OS");

        if (string.IsNullOrWhiteSpace(executablePath) || !File.Exists(executablePath))
            return OperationResult.Fail("Executable path does not exist.", "FILE_NOT_FOUND");

        var fullPath = Path.GetFullPath(executablePath);
        var safeName = Regex.Replace(Path.GetFileNameWithoutExtension(fullPath), @"[^A-Za-z0-9_\-]", "_");
        var outRule = $"{RulePrefix}{safeName}-OUT";
        var inRule = $"{RulePrefix}{safeName}-IN";

        var outRes = await RunNetshAsync(
            $"advfirewall firewall add rule name=\"{outRule}\" dir=out action=block program=\"{fullPath}\" enable=yes",
            ct).ConfigureAwait(false);

        if (outRes.ExitCode != 0)
        {
            var err = string.IsNullOrWhiteSpace(outRes.StdErr) ? outRes.StdOut : outRes.StdErr;
            return OperationResult.Fail($"Could not add outbound firewall block rule (Administrator rights required): {err.Trim()}", "ELEVATION_REQUIRED");
        }

        await RunNetshAsync(
            $"advfirewall firewall add rule name=\"{inRule}\" dir=in action=block program=\"{fullPath}\" enable=yes",
            ct).ConfigureAwait(false);

        return OperationResult.Ok($"Blocked network access (inbound & outbound) for '{Path.GetFileName(fullPath)}' in Windows Firewall.");
    }

    public async Task<OperationResult> UnblockApplicationAsync(string ruleName, CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
            return OperationResult.Fail("Windows Firewall management requires Windows.", "UNSUPPORTED_OS");

        if (string.IsNullOrWhiteSpace(ruleName) || !ruleName.StartsWith(RulePrefix, StringComparison.OrdinalIgnoreCase))
            return OperationResult.Fail("Only BECETTI-BLOCK-* rules can be removed from here.", "INVALID_RULE_NAME");

        var res = await RunNetshAsync($"advfirewall firewall delete rule name=\"{ruleName}\"", ct).ConfigureAwait(false);
        if (res.ExitCode != 0)
        {
            var err = string.IsNullOrWhiteSpace(res.StdErr) ? res.StdOut : res.StdErr;
            return OperationResult.Fail($"Could not remove firewall rule (Administrator rights required): {err.Trim()}", "ELEVATION_REQUIRED");
        }

        // Also remove paired IN/OUT rule if present
        var paired = ruleName.EndsWith("-OUT", StringComparison.OrdinalIgnoreCase)
            ? ruleName[..^4] + "-IN"
            : ruleName.EndsWith("-IN", StringComparison.OrdinalIgnoreCase)
                ? ruleName[..^3] + "-OUT"
                : null;
        if (paired is not null)
            await RunNetshAsync($"advfirewall firewall delete rule name=\"{paired}\"", ct).ConfigureAwait(false);

        return OperationResult.Ok($"Removed firewall block rule '{ruleName}'.");
    }

    internal static IReadOnlyList<FirewallBlockedApp> ParseBecettiRules(string netshOutput)
    {
        var list = new List<FirewallBlockedApp>();
        if (string.IsNullOrWhiteSpace(netshOutput))
            return list;

        string? currentName = null;
        string? currentDir = null;
        string? currentProgram = null;

        void Flush()
        {
            if (!string.IsNullOrWhiteSpace(currentName) &&
                currentName.StartsWith(RulePrefix, StringComparison.OrdinalIgnoreCase))
            {
                list.Add(new FirewallBlockedApp
                {
                    RuleName = currentName,
                    Direction = string.IsNullOrWhiteSpace(currentDir) ? "Outbound" : currentDir,
                    ExecutablePath = string.IsNullOrWhiteSpace(currentProgram) ? "(Any)" : currentProgram
                });
            }
            currentName = null;
            currentDir = null;
            currentProgram = null;
        }

        foreach (var raw in netshOutput.Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0)
            {
                Flush();
                continue;
            }

            if (line.StartsWith("Rule Name:", StringComparison.OrdinalIgnoreCase))
            {
                Flush();
                currentName = line["Rule Name:".Length..].Trim();
            }
            else if (line.StartsWith("Direction:", StringComparison.OrdinalIgnoreCase))
            {
                currentDir = line["Direction:".Length..].Trim();
            }
            else if (line.StartsWith("Program:", StringComparison.OrdinalIgnoreCase))
            {
                currentProgram = line["Program:".Length..].Trim();
            }
        }
        Flush();
        return list;
    }

    private static async Task<(int ExitCode, string StdOut, string StdErr)> RunNetshAsync(string arguments, CancellationToken ct)
    {
        try
        {
            using var proc = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "netsh.exe",
                    Arguments = arguments,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                }
            };
            proc.Start();
            var outTask = proc.StandardOutput.ReadToEndAsync(ct);
            var errTask = proc.StandardError.ReadToEndAsync(ct);
            await proc.WaitForExitAsync(ct).ConfigureAwait(false);
            return (proc.ExitCode, await outTask.ConfigureAwait(false), await errTask.ConfigureAwait(false));
        }
        catch (Exception ex)
        {
            return (-1, string.Empty, ex.Message);
        }
    }
}
