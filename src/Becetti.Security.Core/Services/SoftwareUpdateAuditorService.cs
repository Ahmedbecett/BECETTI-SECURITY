using System.Diagnostics;
using System.Text.RegularExpressions;
using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

public interface ISoftwareUpdateAuditorService
{
    Task<OperationResult<SoftwareUpdateAuditReport>> CheckOutdatedAsync(CancellationToken ct = default);
    Task<OperationResult<string>> UpgradePackageAsync(string packageId, CancellationToken ct = default);
}

/// <summary>
/// Real Outdated Software &amp; Patch Auditor backed by Windows Package Manager (winget):
/// enumerates locally installed software with newer official releases available and supports
/// 1-click silent patching via winget upgrade. Zero simulation.
/// </summary>
public sealed class SoftwareUpdateAuditorService : ISoftwareUpdateAuditorService
{
    private static readonly Regex SafePackageIdRegex = new("^[A-Za-z0-9._+-]{2,128}$", RegexOptions.Compiled);

    public async Task<OperationResult<SoftwareUpdateAuditReport>> CheckOutdatedAsync(CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
            return OperationResult<SoftwareUpdateAuditReport>.Fail("Winget Software Update Auditor requires Windows.", "UNSUPPORTED_OS");

        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "winget.exe",
                Arguments = "upgrade --accept-source-agreements --disable-interactivity",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };

            using var proc = Process.Start(psi);
            if (proc is null)
            {
                return OperationResult<SoftwareUpdateAuditReport>.Ok(new SoftwareUpdateAuditReport
                {
                    WingetAvailable = false,
                    Notes = "winget.exe is not installed or unavailable on this system."
                }, "Windows Package Manager (winget) is not available.");
            }

            var outTask = proc.StandardOutput.ReadToEndAsync(ct);
            var errTask = proc.StandardError.ReadToEndAsync(ct);
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeoutCts.CancelAfter(TimeSpan.FromSeconds(45));
            await proc.WaitForExitAsync(timeoutCts.Token).ConfigureAwait(false);

            var stdout = await outTask.ConfigureAwait(false);
            var packages = ParseWingetUpgradeOutput(stdout);

            var report = new SoftwareUpdateAuditReport
            {
                AuditedAt = DateTimeOffset.UtcNow,
                WingetAvailable = true,
                OutdatedCount = packages.Count,
                Notes = packages.Count == 0
                    ? "All winget-tracked applications are up to date."
                    : $"{packages.Count} application(s) have security/version updates available.",
                Packages = packages
            };

            return OperationResult<SoftwareUpdateAuditReport>.Ok(report, report.Notes);
        }
        catch (System.ComponentModel.Win32Exception)
        {
            return OperationResult<SoftwareUpdateAuditReport>.Ok(new SoftwareUpdateAuditReport
            {
                WingetAvailable = false,
                Notes = "Windows Package Manager (winget) is not installed. Install App Installer from Microsoft Store."
            }, "winget is not installed on this machine.");
        }
        catch (OperationCanceledException)
        {
            return OperationResult<SoftwareUpdateAuditReport>.Fail("Software update check timed out.", "TIMEOUT");
        }
        catch (Exception ex)
        {
            return OperationResult<SoftwareUpdateAuditReport>.Fail($"Software update audit failed: {ex.Message}", "WINGET_ERROR");
        }
    }

    public async Task<OperationResult<string>> UpgradePackageAsync(string packageId, CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
            return OperationResult<string>.Fail("Package upgrade requires Windows.", "UNSUPPORTED_OS");

        if (string.IsNullOrWhiteSpace(packageId) || !SafePackageIdRegex.IsMatch(packageId.Trim()))
            return OperationResult<string>.Fail("Invalid winget package ID.", "INVALID_PACKAGE_ID");

        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "winget.exe",
                Arguments = $"upgrade --id \"{packageId.Trim()}\" --exact --silent --accept-package-agreements --accept-source-agreements --disable-interactivity",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };
            using var proc = Process.Start(psi);
            if (proc is null)
                return OperationResult<string>.Fail("Failed to launch winget.exe.", "LAUNCH_FAILED");

            var stdout = await proc.StandardOutput.ReadToEndAsync(ct).ConfigureAwait(false);
            var stderr = await proc.StandardError.ReadToEndAsync(ct).ConfigureAwait(false);
            await proc.WaitForExitAsync(ct).ConfigureAwait(false);

            if (proc.ExitCode == 0)
                return OperationResult<string>.Ok(packageId.Trim(), $"Successfully upgraded '{packageId.Trim()}' via winget.");

            return OperationResult<string>.Fail($"winget exited with code {proc.ExitCode}. {(string.IsNullOrWhiteSpace(stderr) ? stdout : stderr).Trim()}", "UPGRADE_FAILED");
        }
        catch (Exception ex)
        {
            return OperationResult<string>.Fail($"Upgrade failed: {ex.Message}", "UPGRADE_ERROR");
        }
    }

    internal static List<OutdatedSoftwareItem> ParseWingetUpgradeOutput(string output)
    {
        var list = new List<OutdatedSoftwareItem>();
        if (string.IsNullOrWhiteSpace(output))
            return list;

        var lines = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
        int separatorIndex = -1;
        for (int i = 0; i < lines.Length; i++)
        {
            var trimmed = lines[i].Trim();
            if (trimmed.Length >= 20 && trimmed.All(c => c == '-'))
            {
                separatorIndex = i;
                break;
            }
        }

        if (separatorIndex < 0)
            return list;

        for (int i = separatorIndex + 1; i < lines.Length; i++)
        {
            var line = lines[i].Trim();
            if (string.IsNullOrWhiteSpace(line))
                continue;
            if (line.Contains("upgrades available", StringComparison.OrdinalIgnoreCase) ||
                line.StartsWith("The following packages", StringComparison.OrdinalIgnoreCase))
            {
                break;
            }

            // Split by 2+ consecutive spaces to preserve app names containing single spaces
            var cols = Regex.Split(line, "\\s{2,}")
                .Select(c => c.Trim())
                .Where(c => !string.IsNullOrEmpty(c))
                .ToArray();

            if (cols.Length < 4)
                continue;

            var name = cols[0];
            var id = cols[1];
            var current = cols[2];
            var available = cols[3];
            var source = cols.Length >= 5 ? cols[4] : "winget";

            if (string.Equals(id, "Id", StringComparison.OrdinalIgnoreCase))
                continue;

            list.Add(new OutdatedSoftwareItem
            {
                Name = name,
                PackageId = id,
                InstalledVersion = current,
                AvailableVersion = available,
                Source = source
            });
        }

        return list;
    }
}
