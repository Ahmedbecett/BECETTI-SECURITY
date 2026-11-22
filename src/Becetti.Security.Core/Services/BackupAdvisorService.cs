using System.Diagnostics;
using System.Globalization;
using System.Text.Json;
using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

/// <summary>
/// Reads File History's real service state and System Restore's real
/// shadow copies in one PowerShell call (Get-Service + Win32_ShadowCopy via
/// Get-CimInstance — the exact same source vssadmin's own list reads from).
/// </summary>
public sealed class BackupAdvisorService : IBackupAdvisorService
{
    private static readonly TimeSpan QueryTimeout = TimeSpan.FromSeconds(30);

    public async Task<OperationResult<BackupStatus>> GetStatusAsync(CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
            return OperationResult<BackupStatus>.Fail("Backup Advisor requires Windows.", "UNSUPPORTED_OS");

        const string script =
            "$result = @{}; " +
            "try { $svc = Get-Service -Name fhsvc -ErrorAction Stop; $result.FileHistory = @{Available=$true; Configured=($svc.Status -eq 'Running')} } catch { $result.FileHistory = @{Available=$false; Error=$_.Exception.Message} }; " +
            "try { $shadows = @(Get-CimInstance -ClassName Win32_ShadowCopy -ErrorAction Stop); " +
            "$latest = $shadows | ForEach-Object { $_.InstallDate } | Sort-Object -Descending | Select-Object -First 1; " +
            "$result.Restore = @{Available=$true; Count=$shadows.Count; Latest=$latest} } catch { $result.Restore = @{Available=$false; Error=$_.Exception.Message} }; " +
            "$result | ConvertTo-Json -Depth 5";

        var run = await RunPowerShellAsync(script, QueryTimeout, ct).ConfigureAwait(false);
        if (!run.Success)
            return OperationResult<BackupStatus>.Fail(run.Message, run.ErrorCode);

        try
        {
            return OperationResult<BackupStatus>.Ok(ParseJson(run.Value?.Output ?? string.Empty), "Backup posture read from File History and System Restore.");
        }
        catch (Exception ex)
        {
            return OperationResult<BackupStatus>.Fail($"Could not parse backup status: {ex.Message}", "PARSE_ERROR");
        }
    }

    internal static BackupStatus ParseJson(string json)
    {
        if (string.IsNullOrWhiteSpace(json))
            return new BackupStatus { Available = false, RawError = "No backup data returned." };

        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        bool? fileHistory = null;
        string? error = null;

        if (root.TryGetProperty("FileHistory", out var fh) && fh.ValueKind == JsonValueKind.Object)
        {
            if (fh.TryGetProperty("Available", out var av) && av.ValueKind == JsonValueKind.True &&
                fh.TryGetProperty("Configured", out var cfg))
            {
                fileHistory = cfg.ValueKind == JsonValueKind.True;
            }
            else if (fh.TryGetProperty("Error", out var err))
            {
                error = err.GetString();
            }
        }

        var count = 0;
        DateTimeOffset? latest = null;
        if (root.TryGetProperty("Restore", out var restore) && restore.ValueKind == JsonValueKind.Object &&
            restore.TryGetProperty("Available", out var restoreAvailable) && restoreAvailable.ValueKind == JsonValueKind.True)
        {
            if (restore.TryGetProperty("Count", out var countProp) && countProp.ValueKind == JsonValueKind.Number)
                count = countProp.GetInt32();

            if (restore.TryGetProperty("Latest", out var latestProp) && latestProp.ValueKind == JsonValueKind.String)
            {
                var raw = latestProp.GetString();
                if (!string.IsNullOrWhiteSpace(raw) &&
                    DateTimeOffset.TryParse(raw, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var parsed))
                {
                    latest = parsed;
                }
            }
        }

        return new BackupStatus
        {
            Available = true,
            FileHistoryConfigured = fileHistory,
            RestorePointCount = count,
            LatestRestorePoint = latest,
            RawError = error
        };
    }

    // ---------- Process execution (mirrors DefenderService's pattern) ----------

    private static async Task<OperationResult<ProcessRun>> RunPowerShellAsync(string script, TimeSpan timeout, CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows())
            return OperationResult<ProcessRun>.Fail("This check requires Windows (PowerShell).", "UNSUPPORTED_OS");

        return await RunProcessAsync("powershell.exe",
            $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"{script.Replace("\"", "\\\"")}\"",
            timeout, ct).ConfigureAwait(false);
    }

    private static async Task<OperationResult<ProcessRun>> RunProcessAsync(string fileName, string arguments, TimeSpan? timeout, CancellationToken ct)
    {
        try
        {
            var startInfo = new ProcessStartInfo
            {
                FileName = fileName,
                Arguments = arguments,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };

            using var process = new Process { StartInfo = startInfo };
            process.Start();

            using var timeoutCts = timeout.HasValue
                ? new CancellationTokenSource(timeout.Value)
                : new CancellationTokenSource();
            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct, timeoutCts.Token);

            var outputTask = process.StandardOutput.ReadToEndAsync(linkedCts.Token);
            var errorTask = process.StandardError.ReadToEndAsync(linkedCts.Token);

            await process.WaitForExitAsync(linkedCts.Token).ConfigureAwait(false);
            var output = await outputTask.ConfigureAwait(false);
            var error = await errorTask.ConfigureAwait(false);

            return OperationResult<ProcessRun>.Ok(new ProcessRun(process.ExitCode, output, error));
        }
        catch (OperationCanceledException)
        {
            return OperationResult<ProcessRun>.Fail("The operation timed out or was cancelled.", "TIMEOUT");
        }
        catch (Exception ex)
        {
            return OperationResult<ProcessRun>.Fail($"Failed to run '{fileName}': {ex.Message}", "PROCESS_FAILED");
        }
    }

    private sealed record ProcessRun(int ExitCode, string Output, string Error);
}
