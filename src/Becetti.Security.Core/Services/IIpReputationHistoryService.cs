using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

/// <summary>
/// Local log of real IP-reputation checks performed from BECETTI SECURITY.
/// Only checks that actually completed are recorded — nothing here is
/// seeded or simulated.
/// </summary>
public interface IIpReputationHistoryService
{
    Task RecordAsync(IpReputationCheckRecord record, CancellationToken ct = default);
    Task<IReadOnlyList<IpReputationCheckRecord>> ReadRecentAsync(int count = 100, CancellationToken ct = default);
}
