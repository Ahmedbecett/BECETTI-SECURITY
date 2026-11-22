using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

/// <summary>
/// Cloud Sync: a thin status layer over the existing ICloudService auth
/// client. "Sync" is the app's verified knowledge of the cloud account
/// (reachable, signed in, which email) — there is no second backend or data
/// store being synchronized; everything here already flows through
/// ICloudService's real HTTPS calls.
/// </summary>
public interface ICloudSyncService
{
    /// <summary>Performs a real reachability + auth check against the cloud API and records the result.</summary>
    Task<OperationResult<CloudSyncStatus>> SyncNowAsync(CancellationToken ct = default);

    /// <summary>Last known status without making a new network call (based on the last SyncNowAsync).</summary>
    CloudSyncStatus? LastKnownStatus { get; }
}
