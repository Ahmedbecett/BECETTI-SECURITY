using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Becetti.Security.Api.Controllers;

namespace Becetti.Security.Api.Tests;

public sealed class ApiTests : IClassFixture<BecettiApiFactory>
{
    private readonly BecettiApiFactory _factory;

    public ApiTests(BecettiApiFactory factory)
    {
        _factory = factory;
    }

    private static readonly JsonSerializerOptions Json = new() { PropertyNameCaseInsensitive = true };

    [Fact]
    public async Task Health_ReturnsOk()
    {
        using var client = _factory.CreateClient();
        var response = await client.GetAsync("/health");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("ok", body.GetProperty("status").GetString());
    }

    [Fact]
    public async Task Auth_RegisterLoginMe_Flow()
    {
        using var client = _factory.CreateClient();
        var email = $"user-{Guid.NewGuid():N}@example.test";

        var register = await client.PostAsJsonAsync("/api/v1/auth/register", new { email, password = "correct-horse-123" });
        Assert.Equal(HttpStatusCode.OK, register.StatusCode);

        var tokens = await register.Content.ReadFromJsonAsync<JsonElement>();
        var accessToken = tokens.GetProperty("accessToken").GetString();
        Assert.False(string.IsNullOrWhiteSpace(accessToken));

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        var me = await client.GetAsync("/api/v1/auth/me");
        Assert.Equal(HttpStatusCode.OK, me.StatusCode);
        var meBody = await me.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(email, meBody.GetProperty("email").GetString());
    }

    [Fact]
    public async Task Auth_LoginWrongPassword_ReturnsUnauthorized()
    {
        using var client = _factory.CreateClient();
        var email = $"user-{Guid.NewGuid():N}@example.test";

        await client.PostAsJsonAsync("/api/v1/auth/register", new { email, password = "correct-horse-123" });
        var login = await client.PostAsJsonAsync("/api/v1/auth/login", new { email, password = "wrong-password-456" });
        Assert.Equal(HttpStatusCode.Unauthorized, login.StatusCode);
    }

    [Fact]
    public async Task Reputation_WithoutProvider_ReturnsUnknownHonestly()
    {
        using var client = _factory.CreateClient();
        var email = $"user-{Guid.NewGuid():N}@example.test";

        var register = await client.PostAsJsonAsync("/api/v1/auth/register", new { email, password = "correct-horse-123" });
        var tokens = await register.Content.ReadFromJsonAsync<JsonElement>();
        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", tokens.GetProperty("accessToken").GetString());

        var sha256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        var response = await client.PostAsJsonAsync("/api/v1/reputation/check", new { sha256 });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("unknown", body.GetProperty("verdict").GetString());
        Assert.Equal("no-provider-configured", body.GetProperty("source").GetString());
    }

    [Fact]
    public async Task Reputation_Unauthenticated_ReturnsUnauthorized()
    {
        using var client = _factory.CreateClient();
        var sha256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        var response = await client.PostAsJsonAsync("/api/v1/reputation/check", new { sha256 });
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Updates_NoReleases_ReturnsNoUpdate()
    {
        using var client = _factory.CreateClient();
        var email = $"user-{Guid.NewGuid():N}@example.test";

        var register = await client.PostAsJsonAsync("/api/v1/auth/register", new { email, password = "correct-horse-123" });
        var tokens = await register.Content.ReadFromJsonAsync<JsonElement>();
        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", tokens.GetProperty("accessToken").GetString());

        var response = await client.GetAsync("/api/v1/updates/check?currentVersion=1.0.0&channel=stable");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.False(body.GetProperty("updateAvailable").GetBoolean());
    }

    [Fact]
    public async Task Devices_HeartbeatListRemove_Flow()
    {
        using var client = _factory.CreateClient();
        var email = $"user-{Guid.NewGuid():N}@example.test";

        var register = await client.PostAsJsonAsync("/api/v1/auth/register", new { email, password = "correct-horse-123" });
        var tokens = await register.Content.ReadFromJsonAsync<JsonElement>();
        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", tokens.GetProperty("accessToken").GetString());

        var deviceId = Guid.NewGuid().ToString("N");
        var heartbeat = await client.PostAsJsonAsync("/api/v1/devices/heartbeat", new
        {
            deviceId,
            deviceName = "Test-PC",
            platform = "Windows",
            appVersion = "1.0.0"
        });
        Assert.Equal(HttpStatusCode.OK, heartbeat.StatusCode);
        var heartbeatBody = await heartbeat.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(deviceId, heartbeatBody.GetProperty("deviceId").GetString());
        Assert.Equal("Test-PC", heartbeatBody.GetProperty("deviceName").GetString());

        // A second heartbeat for the same deviceId updates the existing row, it doesn't duplicate it.
        await client.PostAsJsonAsync("/api/v1/devices/heartbeat", new
        {
            deviceId,
            deviceName = "Test-PC-Renamed",
            platform = "Windows",
            appVersion = "1.0.1"
        });

        var list = await client.GetAsync("/api/v1/devices");
        Assert.Equal(HttpStatusCode.OK, list.StatusCode);
        var devices = await list.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(1, devices.GetArrayLength());
        Assert.Equal("Test-PC-Renamed", devices[0].GetProperty("deviceName").GetString());
        Assert.Equal("1.0.1", devices[0].GetProperty("appVersion").GetString());

        var remove = await client.DeleteAsync($"/api/v1/devices/{deviceId}");
        Assert.Equal(HttpStatusCode.NoContent, remove.StatusCode);

        var listAfterRemove = await client.GetAsync("/api/v1/devices");
        var devicesAfterRemove = await listAfterRemove.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(0, devicesAfterRemove.GetArrayLength());
    }

    [Fact]
    public async Task Devices_Unauthenticated_ReturnsUnauthorized()
    {
        using var client = _factory.CreateClient();
        var response = await client.GetAsync("/api/v1/devices");
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Devices_OneUserCannotSeeAnothersDevices()
    {
        using var client = _factory.CreateClient();

        async Task<string> RegisterAndGetTokenAsync()
        {
            var email = $"user-{Guid.NewGuid():N}@example.test";
            var register = await client.PostAsJsonAsync("/api/v1/auth/register", new { email, password = "correct-horse-123" });
            var tokens = await register.Content.ReadFromJsonAsync<JsonElement>();
            return tokens.GetProperty("accessToken").GetString()!;
        }

        var userAToken = await RegisterAndGetTokenAsync();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", userAToken);
        await client.PostAsJsonAsync("/api/v1/devices/heartbeat", new
        {
            deviceId = Guid.NewGuid().ToString("N"),
            deviceName = "User-A-PC",
            platform = "Windows",
            appVersion = "1.0.0"
        });

        var userBToken = await RegisterAndGetTokenAsync();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", userBToken);
        var listForB = await client.GetAsync("/api/v1/devices");
        var devicesForB = await listForB.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(0, devicesForB.GetArrayLength());
    }

    [Theory]
    [InlineData("1.0.1", "1.0.0", 1)]
    [InlineData("1.0.0", "1.0.1", -1)]
    [InlineData("1.0.0", "1.0.0", 0)]
    [InlineData("2.0.0", "1.9.9", 1)]
    [InlineData("1.10.0", "1.9.0", 1)]
    public void CompareVersions_Cases(string a, string b, int expectedSign)
    {
        var result = UpdatesController.CompareVersions(a, b);
        Assert.Equal(expectedSign, Math.Sign(result));
    }
}
