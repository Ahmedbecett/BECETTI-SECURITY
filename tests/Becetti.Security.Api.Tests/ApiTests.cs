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
