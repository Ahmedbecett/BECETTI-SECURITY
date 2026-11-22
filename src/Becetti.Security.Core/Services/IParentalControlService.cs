using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

/// <summary>
/// Real website blocking using the Windows hosts file
/// (%SystemRoot%\System32\drivers\etc\hosts) — the same mechanism Windows
/// itself consults for every DNS lookup. Entries BECETTI SECURITY added are
/// marked with a recognizable comment tag so they can be listed and removed
/// without touching any other line a user or another program added.
/// Changing the hosts file requires Administrator; this service reports
/// that honestly rather than silently failing.
/// </summary>
public interface IParentalControlService
{
    /// <summary>True when this process can write the hosts file (i.e. is elevated).</summary>
    bool CanManageBlocklist { get; }

    Task<OperationResult<IReadOnlyList<BlockedDomainInfo>>> GetBlockedDomainsAsync(CancellationToken ct = default);

    Task<OperationResult> BlockDomainAsync(string domain, CancellationToken ct = default);

    Task<OperationResult> UnblockDomainAsync(string domain, CancellationToken ct = default);
}
