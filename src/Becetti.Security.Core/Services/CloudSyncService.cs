using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

/// <summary>
/// Calls ICloudService's real GetHealthAsync/GetCurrentUserEmailAsync and
/// records the verified outcome. Never reports "synced" without a real,
/// current HTTPS round trip having just succeeded.
/// </summary>
public sealed class CloudSyncService : ICloudSyncService
{
    private readonly ICloudService _cloud;
    private readonly ISettingsService _settings;

    public CloudSyncService(ICloudService cloud, ISettingsService settings)
    {
        _cloud = cloud;
        _settings = settings;
    }

    public CloudSyncStatus? LastKnownStatus { get; private set; }

    public async Task<OperationResult<CloudSyncStatus>> SyncNowAsync(CancellationToken ct = default)
    {
        if (!_cloud.IsConfigured)
        {
            var notConfigured = new CloudSyncStatus { Configured = false, Reachable = false, Authenticated = false };
            LastKnownStatus = notConfigured;
            return OperationResult<CloudSyncStatus>.Fail(
                "Cloud API is not configured. Enter the BECETTI SECURITY API URL in Settings to enable Cloud Sync.",
                "NOT_CONFIGURED");
        }

        var health = await _cloud.GetHealthAsync(ct).ConfigureAwait(false);
        if (!health.Success)
        {
            var unreachable = new CloudSyncStatus
            {
                Configured = true,
                Reachable = false,
                Authenticated = _cloud.IsAuthenticated,
                RawError = health.Message
            };
            LastKnownStatus = unreachable;
            return OperationResult<CloudSyncStatus>.Fail(health.Message, health.ErrorCode);
        }

        string? email = null;
        if (_cloud.IsAuthenticated)
        {
            var me = await _cloud.GetCurrentUserEmailAsync(ct).ConfigureAwait(false);
            if (me.Success)
                email = me.Value;
        }

        _settings.Current.LastCloudSyncAt = DateTimeOffset.Now;
        await _settings.SaveAsync(ct).ConfigureAwait(false);

        var status = new CloudSyncStatus
        {
            Configured = true,
            Reachable = true,
            Authenticated = _cloud.IsAuthenticated,
            AccountEmail = email,
            LastSyncedAt = _settings.Current.LastCloudSyncAt
        };
        LastKnownStatus = status;

        return OperationResult<CloudSyncStatus>.Ok(
            status,
            _cloud.IsAuthenticated ? $"Cloud reachable, signed in as {email}." : "Cloud reachable; not signed in.");
    }
}
