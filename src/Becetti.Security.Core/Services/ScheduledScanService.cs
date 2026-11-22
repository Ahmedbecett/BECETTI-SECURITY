using System.Diagnostics;
using System.Globalization;
using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

/// <summary>
/// Creates, queries and removes one real Windows Scheduled Task through
/// schtasks.exe — the exact same tool/engine the Task Scheduler app itself
/// is a UI for. The task's action runs MpCmdRun.exe (via IDefenderService),
/// so the scan it performs is a genuine Defender scan, not a simulated one.
/// </summary>
public sealed class ScheduledScanService : IScheduledScanService
{
    private const string TaskName = "BecettiSecurity_ScheduledScan";
    private static readonly TimeSpan QueryTimeout = TimeSpan.FromSeconds(20);

    private readonly IDefenderService _defender;

    public ScheduledScanService(IDefenderService defender)
    {
        _defender = defender;
    }

    public async Task<OperationResult<ScheduledScanInfo>> GetStatusAsync(CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
            return OperationResult<ScheduledScanInfo>.Fail("Scheduled Scan requires Windows.", "UNSUPPORTED_OS");

        var run = await RunAsync("schtasks.exe",
            $"/Query /TN \"{TaskName}\" /FO LIST /V",
            QueryTimeout, ct).ConfigureAwait(false);

        if (!run.Success || run.Value is null)
            return OperationResult<ScheduledScanInfo>.Fail(run.Message, run.ErrorCode);

        if (run.Value.ExitCode != 0)
        {
            // schtasks exits non-zero (and writes "ERROR: The system cannot find the file
            // specified.") when the task simply does not exist yet — that is the honest
            // "no scheduled scan configured" state, not a failure to report.
            return OperationResult<ScheduledScanInfo>.Ok(
                new ScheduledScanInfo { Exists = false, TaskName = TaskName },
                "No scheduled scan is currently configured.");
        }

        return OperationResult<ScheduledScanInfo>.Ok(ParseQueryOutput(run.Value.Output), "Scheduled scan state read from Task Scheduler.");
    }

    internal static ScheduledScanInfo ParseQueryOutput(string output)
    {
        string? Field(string label)
        {
            foreach (var line in output.Split('\n'))
            {
                var trimmed = line.TrimEnd('\r');
                if (trimmed.StartsWith(label, StringComparison.OrdinalIgnoreCase))
                {
                    var idx = trimmed.IndexOf(':');
                    return idx >= 0 ? trimmed[(idx + 1)..].Trim() : null;
                }
            }
            return null;
        }

        // The scan type isn't a native schtasks property; it is recovered from the
        // actual command line the task runs (MpCmdRun.exe -Scan -ScanType N).
        var taskToRun = Field("Task To Run") ?? string.Empty;
        var scanType = taskToRun.Contains("-ScanType 2", StringComparison.OrdinalIgnoreCase)
            ? DefenderScanType.Full
            : DefenderScanType.Quick;

        return new ScheduledScanInfo
        {
            Exists = true,
            TaskName = TaskName,
            ScanType = scanType,
            ScheduleDescription = Field("Schedule Type") is { } st && Field("Start Time") is { } time
                ? $"{st} at {time}"
                : Field("Schedule Type"),
            NextRunTime = ParseDate(Field("Next Run Time")),
            LastRunTime = ParseDate(Field("Last Run Time")),
            LastTaskResult = Field("Last Result")
        };
    }

    private static DateTimeOffset? ParseDate(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw) || raw.Equals("N/A", StringComparison.OrdinalIgnoreCase))
            return null;

        return DateTimeOffset.TryParse(raw, CultureInfo.CurrentCulture, DateTimeStyles.AssumeLocal, out var value)
            ? value
            : null;
    }

    public async Task<OperationResult> ScheduleDailyScanAsync(DefenderScanType scanType, int hour, CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
            return OperationResult.Fail("Scheduled Scan requires Windows.", "UNSUPPORTED_OS");

        if (!ElevationHelper.IsElevated())
            return OperationResult.Fail(
                "Creating a scheduled scan requires an administrator. Restart BECETTI SECURITY as administrator from Settings.",
                "ELEVATION_REQUIRED");

        if (hour is < 0 or > 23)
            return OperationResult.Fail("The hour must be between 0 and 23.", "INVALID_HOUR");

        var mpCmdRun = _defender.FindMpCmdRun();
        if (mpCmdRun is null)
            return OperationResult.Fail("Microsoft Defender's MpCmdRun.exe could not be located.", "DEFENDER_NOT_FOUND");

        var scanArg = scanType == DefenderScanType.Full ? "-Scan -ScanType 2" : "-Scan -ScanType 1";
        var startTime = $"{hour:00}:00";

        var createArgs =
            $"/Create /TN \"{TaskName}\" /TR \"\\\"{mpCmdRun}\\\" {scanArg}\" " +
            $"/SC DAILY /ST {startTime} /RU SYSTEM /RL HIGHEST /F";

        var run = await RunAsync("schtasks.exe", createArgs, QueryTimeout, ct).ConfigureAwait(false);
        if (!run.Success || run.Value is null)
            return OperationResult.Fail(run.Message, run.ErrorCode);

        if (run.Value.ExitCode != 0)
            return OperationResult.Fail(
                string.IsNullOrWhiteSpace(run.Value.Error) ? "schtasks.exe could not create the scheduled task." : run.Value.Error,
                "SCHTASKS_FAILED");

        // Re-query the task from Task Scheduler itself to verify the create actually
        // succeeded, rather than trusting schtasks' exit code alone.
        var verify = await GetStatusAsync(ct).ConfigureAwait(false);
        if (!verify.Success || verify.Value is null || !verify.Value.Exists)
            return OperationResult.Fail("The scheduled scan could not be confirmed after creation.", "VERIFICATION_FAILED");

        return OperationResult.Ok($"Daily {scanType} scan scheduled for {startTime} via Task Scheduler.");
    }

    public async Task<OperationResult> RemoveScheduledScanAsync(CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
            return OperationResult.Fail("Scheduled Scan requires Windows.", "UNSUPPORTED_OS");

        if (!ElevationHelper.IsElevated())
            return OperationResult.Fail(
                "Removing the scheduled scan requires an administrator. Restart BECETTI SECURITY as administrator from Settings.",
                "ELEVATION_REQUIRED");

        var run = await RunAsync("schtasks.exe", $"/Delete /TN \"{TaskName}\" /F", QueryTimeout, ct).ConfigureAwait(false);
        if (!run.Success || run.Value is null)
            return OperationResult.Fail(run.Message, run.ErrorCode);

        // Exit code non-zero here just means the task was already gone — treat that as
        // success for a "remove" operation rather than surfacing a confusing error.
        return OperationResult.Ok("No scheduled scan remains configured.");
    }

    // ---------- Process execution (mirrors DefenderService's pattern) ----------

    private static async Task<OperationResult<ProcessRun>> RunAsync(string fileName, string arguments, TimeSpan timeout, CancellationToken ct)
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

            using var timeoutCts = new CancellationTokenSource(timeout);
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
