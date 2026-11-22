using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

/// <summary>
/// Local log of real VirusTotal checks performed from BECETTI SECURITY. Only
/// scans that actually completed, were found not-indexed, or genuinely
/// failed are recorded — nothing here is seeded or simulated.
/// </summary>
public interface IThreatIntelHistoryService
{
    Task RecordAsync(ThreatIntelScanRecord record, CancellationToken ct = default);
    Task<IReadOnlyList<ThreatIntelScanRecord>> ReadRecentAsync(int count = 100, CancellationToken ct = default);
}
