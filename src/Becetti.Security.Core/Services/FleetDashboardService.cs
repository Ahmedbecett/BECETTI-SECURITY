using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

public interface IFleetDashboardService
{
    Task<OperationResult<FleetDashboardReport>> LoadFleetAsync(CancellationToken ct = default);
    Task<OperationResult<FleetDeviceStatus>> SyncCurrentDeviceHeartbeatAsync(CancellationToken ct = default);
    Task<OperationResult> RemoveFleetDeviceAsync(string deviceId, CancellationToken ct = default);
}

/// <summary>
/// #11: Multi-Device Cloud Fleet Management Service.
/// Connects directly to Becetti.Security.Api via ICloudService (/api/devices) to enroll/heartbeat
/// this Windows endpoint and monitor every real device registered under the user's cloud account.
/// Never invents fleet devices when cloud is not configured or unauthenticated.
/// </summary>
public sealed class FleetDashboardService : IFleetDashboardService
{
    private readonly ICloudService _cloud;
    private readonly ISettingsService _settings;
    private readonly IAppUpdaterService _updater;

    public FleetDashboardService(ICloudService cloud, ISettingsService settings, IAppUpdaterService updater)
    {
        _cloud = cloud;
        _settings = settings;
        _updater = updater;
    }

    public async Task<OperationResult<FleetDashboardReport>> LoadFleetAsync(CancellationToken ct = default)
    {
        if (!_cloud.IsConfigured)
        {
            var r = new FleetDashboardReport
            {
                CloudConfigured = false,
                Authenticated = false,
                CloudEndpoint = "(Not configured)",
                Summary = "Cloud Fleet API is not configured yet. Set your BECETTI Cloud API URL in Settings and sign in on the Cloud page to manage multiple Windows endpoints."
            };
            return OperationResult<FleetDashboardReport>.Ok(r, r.Summary);
        }

        if (!_cloud.IsAuthenticated)
        {
            var r = new FleetDashboardReport
            {
                CloudConfigured = true,
                Authenticated = false,
                CloudEndpoint = _settings.Current.ApiBaseUrl,
                Summary = "Cloud API is configured, but you are not signed in. Sign in on the Cloud Security page to view and sync your multi-device fleet."
            };
            return OperationResult<FleetDashboardReport>.Ok(r, r.Summary);
        }

        var devRes = await _cloud.GetDevicesAsync(ct).ConfigureAwait(false);
        if (!devRes.Success || devRes.Value is null)
            return OperationResult<FleetDashboardReport>.Fail(devRes.Message, devRes.ErrorCode);

        var mapped = devRes.Value.Select(d => new FleetDeviceStatus
        {
            DeviceId = d.DeviceId,
            DeviceName = d.DeviceName,
            OsVersion = d.Platform,
            AppVersion = d.AppVersion,
            LastSeenUtc = d.LastSeenAt,
            IsCurrentDevice = d.IsThisDevice
        }).ToList();

        var report = new FleetDashboardReport
        {
            CloudConfigured = true,
            Authenticated = true,
            CloudEndpoint = _settings.Current.ApiBaseUrl,
            TotalDevices = mapped.Count,
            Devices = mapped,
            Summary = $"Connected to Cloud Fleet ({_settings.Current.ApiBaseUrl}): {mapped.Count} real device(s) registered."
        };

        return OperationResult<FleetDashboardReport>.Ok(report, report.Summary);
    }

    public async Task<OperationResult<FleetDeviceStatus>> SyncCurrentDeviceHeartbeatAsync(CancellationToken ct = default)
    {
        if (!_cloud.IsConfigured || !_cloud.IsAuthenticated)
            return OperationResult<FleetDeviceStatus>.Fail("Configure Cloud API URL in Settings and sign in on the Cloud page first.", "NOT_AUTHENTICATED");

        var res = await _cloud.SendDeviceHeartbeatAsync(
            Environment.MachineName,
            $"Windows {Environment.OSVersion.Version}",
            _updater.GetCurrentVersion(),
            ct).ConfigureAwait(false);

        if (!res.Success || res.Value is null)
            return OperationResult<FleetDeviceStatus>.Fail(res.Message, res.ErrorCode);

        var d = res.Value;
        return OperationResult<FleetDeviceStatus>.Ok(new FleetDeviceStatus
        {
            DeviceId = d.DeviceId,
            DeviceName = d.DeviceName,
            OsVersion = d.Platform,
            AppVersion = d.AppVersion,
            LastSeenUtc = d.LastSeenAt,
            IsCurrentDevice = true
        }, $"Synced heartbeat for '{d.DeviceName}' to BECETTI Cloud Fleet.");
    }

    public Task<OperationResult> RemoveFleetDeviceAsync(string deviceId, CancellationToken ct = default) =>
        _cloud.RemoveDeviceAsync(deviceId, ct);
}
