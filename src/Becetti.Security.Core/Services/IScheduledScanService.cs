using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

/// <summary>
/// Scheduled Scan: manages a real Windows Scheduled Task (via schtasks.exe)
/// that runs a genuine Defender scan through MpCmdRun.exe. BECETTI SECURITY
/// never runs its own background timer pretending to scan while closed — the
/// task is registered in, and fully visible/editable from, Task Scheduler
/// itself.
/// </summary>
public interface IScheduledScanService
{
    /// <summary>Query the real scheduled task's current state from Task Scheduler.</summary>
    Task<OperationResult<ScheduledScanInfo>> GetStatusAsync(CancellationToken ct = default);

    /// <summary>
    /// Create or replace the scheduled task to run a Defender scan daily at
    /// <paramref name="hour"/>:00 local time (requires elevation).
    /// </summary>
    Task<OperationResult> ScheduleDailyScanAsync(DefenderScanType scanType, int hour, CancellationToken ct = default);

    /// <summary>Remove the scheduled task (requires elevation). A no-op success if none exists.</summary>
    Task<OperationResult> RemoveScheduledScanAsync(CancellationToken ct = default);
}
