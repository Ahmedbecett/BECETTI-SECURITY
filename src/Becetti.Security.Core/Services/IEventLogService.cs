using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

/// <summary>
/// Local security event history. Only events that actually happened are
/// recorded (real scans, real detections, real failures). Nothing is seeded.
/// </summary>
public interface IEventLogService
{
    Task RecordAsync(string type, string summary, bool success, string? detail = null, CancellationToken ct = default);
    Task<IReadOnlyList<SecurityEvent>> ReadRecentAsync(int count = 200, CancellationToken ct = default);
}
