using Becetti.Security.Core.Services;

namespace Becetti.Security.Core.Tests;

public sealed class CloudServiceTests
{
    private static CloudService CreateCloud(string apiUrl)
    {
        var dir = Path.Combine(Path.GetTempPath(), "becetti-test-" + Guid.NewGuid());
        var settings = new SettingsService(dir);
        settings.Current.ApiBaseUrl = apiUrl;
        var tokens = new TokenStore(dir);
        return new CloudService(new HttpClient(), settings, tokens);
    }

    [Fact]
    public async Task Health_NotConfigured_ReturnsNotConfigured()
    {
        var cloud = CreateCloud(string.Empty);
        Assert.False(cloud.IsConfigured);

        var result = await cloud.GetHealthAsync();
        Assert.False(result.Success);
        Assert.Equal("NOT_CONFIGURED", result.ErrorCode);
    }

    [Fact]
    public async Task Reputation_InvalidHash_RejectedWithoutNetwork()
    {
        var cloud = CreateCloud("https://api.example.test");
        var result = await cloud.CheckReputationAsync("not-a-hash");
        Assert.False(result.Success);
        Assert.Equal("INVALID_HASH", result.ErrorCode);
    }

    [Fact]
    public async Task Health_UnreachableHost_ReturnsOfflineFailure()
    {
        // Port 9 (discard) on loopback is closed: connection refused, fast failure.
        var cloud = CreateCloud("http://127.0.0.1:9");
        var result = await cloud.GetHealthAsync();
        Assert.False(result.Success);
        Assert.Equal("OFFLINE", result.ErrorCode);
    }

    [Fact]
    public async Task Devices_NotConfigured_ReturnsNotConfigured()
    {
        var cloud = CreateCloud(string.Empty);

        var heartbeat = await cloud.SendDeviceHeartbeatAsync("Test-PC", "Windows", "1.0.0");
        Assert.False(heartbeat.Success);
        Assert.Equal("NOT_CONFIGURED", heartbeat.ErrorCode);

        var list = await cloud.GetDevicesAsync();
        Assert.False(list.Success);
        Assert.Equal("NOT_CONFIGURED", list.ErrorCode);

        var remove = await cloud.RemoveDeviceAsync("some-device-id");
        Assert.False(remove.Success);
        Assert.Equal("NOT_CONFIGURED", remove.ErrorCode);
    }

    [Fact]
    public async Task Devices_ConfiguredButNotSignedIn_ReturnsNotAuthenticated()
    {
        var cloud = CreateCloud("https://api.example.test");

        var heartbeat = await cloud.SendDeviceHeartbeatAsync("Test-PC", "Windows", "1.0.0");
        Assert.False(heartbeat.Success);
        Assert.Equal("NOT_AUTHENTICATED", heartbeat.ErrorCode);

        var list = await cloud.GetDevicesAsync();
        Assert.False(list.Success);
        Assert.Equal("NOT_AUTHENTICATED", list.ErrorCode);

        var remove = await cloud.RemoveDeviceAsync("some-device-id");
        Assert.False(remove.Success);
        Assert.Equal("NOT_AUTHENTICATED", remove.ErrorCode);
    }
}
