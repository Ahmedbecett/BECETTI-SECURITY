using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

/// <summary>
/// Local log of real data-breach monitoring checks performed from BECETTI
/// SECURITY. Only checks that actually completed are recorded — nothing
/// here is seeded or simulated. Password checks never record the password
/// or any part of its hash, only whether it was found and how many times.
/// </summary>
public interface IDataBreachHistoryService
{
    Task RecordAsync(DataBreachCheckRecord record, CancellationToken ct = default);
    Task<IReadOnlyList<DataBreachCheckRecord>> ReadRecentAsync(int count = 100, CancellationToken ct = default);
}
