using System.Diagnostics;
using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

public interface INetworkKillSwitchService
{
    Task<OperationResult<NetworkIsolationStatus>> GetStatusAsync(CancellationToken ct = default);
    Task<OperationResult<NetworkIsolationStatus>> IsolateHostAsync(CancellationToken ct = default);
    Task<OperationResult<NetworkIsolationStatus>> RestoreNetworkAsync(CancellationToken ct = default);
}

/// <summary>
/// Real Emergency Network Kill-Switch / Host Isolation via Windows Defender Firewall (netsh advfirewall).
/// When engaged, switches all firewall profiles to blockinbound,blockoutbound and marks the state
/// with a dedicated rule (BECETTI-KILLSWITCH-ACTIVE). Restoring reverts to blockinbound,allowoutbound
/// and removes the isolation marker. Zero simulation.
/// </summary>
public sealed class NetworkKillSwitchService : INetworkKillSwitchService
{
    private const string MarkerRuleName = "BECETTI-KILLSWITCH-ACTIVE";

    public async Task<OperationResult<NetworkIsolationStatus>> GetStatusAsync(CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
            return OperationResult<NetworkIsolationStatus>.Fail("Network Kill-Switch requires Windows.", "UNSUPPORTED_OS");

        var check = await RunNetshAsync(new[] { "advfirewall", "firewall", "show", "rule", $"name={MarkerRuleName}" }, ct).ConfigureAwait(false);
        bool isolated = check.ExitCode == 0 && check.StdOut.Contains(MarkerRuleName, StringComparison.OrdinalIgnoreCase);

        var status = new NetworkIsolationStatus
        {
            IsIsolated = isolated,
            CheckedAt = DateTimeOffset.UtcNow,
            Summary = isolated
                ? "HOST ISOLATED — All outbound & inbound network traffic is blocked by BECETTI Emergency Kill-Switch."
                : "Normal network access — Emergency Kill-Switch is disengaged."
        };
        return OperationResult<NetworkIsolationStatus>.Ok(status, status.Summary);
    }

    public async Task<OperationResult<NetworkIsolationStatus>> IsolateHostAsync(CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
            return OperationResult<NetworkIsolationStatus>.Fail("Network Kill-Switch requires Windows.", "UNSUPPORTED_OS");

        var policy = await RunNetshAsync(new[] { "advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,blockoutbound" }, ct).ConfigureAwait(false);
        if (policy.ExitCode != 0)
        {
            return OperationResult<NetworkIsolationStatus>.Fail(
                $"Could not isolate host (Administrator privileges required): {FirstMessage(policy)}",
                "ELEVATION_REQUIRED");
        }

        await RunNetshAsync(new[] { "advfirewall", "set", "allprofiles", "state", "on" }, ct).ConfigureAwait(false);
        await RunNetshAsync(new[] { "advfirewall", "firewall", "delete", "rule", $"name={MarkerRuleName}" }, ct).ConfigureAwait(false);
        await RunNetshAsync(new[]
        {
            "advfirewall", "firewall", "add", "rule",
            $"name={MarkerRuleName}",
            "dir=out", "action=block", "remoteip=any", "enable=yes", "profile=any",
            "description=BECETTI SECURITY Emergency Network Kill-Switch"
        }, ct).ConfigureAwait(false);

        return await GetStatusAsync(ct).ConfigureAwait(false);
    }

    public async Task<OperationResult<NetworkIsolationStatus>> RestoreNetworkAsync(CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
            return OperationResult<NetworkIsolationStatus>.Fail("Network Kill-Switch requires Windows.", "UNSUPPORTED_OS");

        var policy = await RunNetshAsync(new[] { "advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,allowoutbound" }, ct).ConfigureAwait(false);
        if (policy.ExitCode != 0)
        {
            return OperationResult<NetworkIsolationStatus>.Fail(
                $"Could not restore network policy (Administrator privileges required): {FirstMessage(policy)}",
                "ELEVATION_REQUIRED");
        }

        await RunNetshAsync(new[] { "advfirewall", "firewall", "delete", "rule", $"name={MarkerRuleName}" }, ct).ConfigureAwait(false);
        return await GetStatusAsync(ct).ConfigureAwait(false);
    }

    private static string FirstMessage((int ExitCode, string StdOut, string StdErr) r) =>
        !string.IsNullOrWhiteSpace(r.StdErr) ? r.StdErr.Trim() : r.StdOut.Trim();

    private static async Task<(int ExitCode, string StdOut, string StdErr)> RunNetshAsync(string[] args, CancellationToken ct)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "netsh.exe",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };
            foreach (var a in args) psi.ArgumentList.Add(a);

            using var proc = Process.Start(psi);
            if (proc is null) return (-1, string.Empty, "Could not start netsh.exe.");

            var stdout = await proc.StandardOutput.ReadToEndAsync(ct).ConfigureAwait(false);
            var stderr = await proc.StandardError.ReadToEndAsync(ct).ConfigureAwait(false);
            await proc.WaitForExitAsync(ct).ConfigureAwait(false);
            return (proc.ExitCode, stdout, stderr);
        }
        catch (Exception ex)
        {
            return (-1, string.Empty, ex.Message);
        }
    }
}
