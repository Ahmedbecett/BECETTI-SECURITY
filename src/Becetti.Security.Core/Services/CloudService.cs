using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

/// <summary>
/// HTTPS client for the BECETTI SECURITY cloud API. TLS verification is never
/// disabled. Offline or unconfigured states are reported honestly.
/// </summary>
public sealed class CloudService : ICloudService
{
    private static readonly TimeSpan RequestTimeout = TimeSpan.FromSeconds(15);

    private readonly HttpClient _http;
    private readonly ISettingsService _settings;
    private readonly ITokenStore _tokens;

    public CloudService(HttpClient http, ISettingsService settings, ITokenStore tokens)
    {
        _http = http;
        _settings = settings;
        _tokens = tokens;
    }

    public bool IsConfigured => !string.IsNullOrWhiteSpace(_settings.Current.ApiBaseUrl);

    public bool IsAuthenticated => !string.IsNullOrWhiteSpace(AccessToken);

    public string? AccessToken { get; private set; }

    private string BaseUrl => _settings.Current.ApiBaseUrl.TrimEnd('/');

    public async Task<OperationResult<CloudHealth>> GetHealthAsync(CancellationToken ct = default)
    {
        var notConfigured = CheckConfigured();
        if (notConfigured is not null)
            return OperationResult<CloudHealth>.Fail(notConfigured.Message, notConfigured.ErrorCode);

        return await SendAsync<HealthDto>(HttpMethod.Get, "/health", null, ct).ContinueWith<OperationResult<CloudHealth>>(t =>
        {
            var r = t.Result;
            if (!r.Success || r.Value is null)
                return OperationResult<CloudHealth>.Fail(r.Message, r.ErrorCode);
            return OperationResult<CloudHealth>.Ok(new CloudHealth
            {
                Status = r.Value.Status,
                Version = r.Value.Version,
                ServerTime = r.Value.ServerTime
            }, "Cloud API is reachable.");
        }, ct).ConfigureAwait(false);
    }

    public async Task<OperationResult<AuthTokens>> LoginAsync(string email, string password, CancellationToken ct = default)
    {
        var notConfigured = CheckConfigured();
        if (notConfigured is not null)
            return OperationResult<AuthTokens>.Fail(notConfigured.Message, notConfigured.ErrorCode);

        var payload = new { email, password };
        var result = await SendAsync<TokenDto>(HttpMethod.Post, "/api/v1/auth/login", payload, ct).ConfigureAwait(false);
        if (!result.Success || result.Value is null)
            return OperationResult<AuthTokens>.Fail(result.Message, result.ErrorCode);

        var tokens = MapTokens(result.Value);
        AccessToken = tokens.AccessToken;
        await _tokens.SaveAsync(tokens, ct).ConfigureAwait(false);
        return OperationResult<AuthTokens>.Ok(tokens, "Signed in.");
    }

    public async Task<OperationResult<AuthTokens>> RegisterAsync(string email, string password, CancellationToken ct = default)
    {
        var notConfigured = CheckConfigured();
        if (notConfigured is not null)
            return OperationResult<AuthTokens>.Fail(notConfigured.Message, notConfigured.ErrorCode);

        var payload = new { email, password };
        var result = await SendAsync<TokenDto>(HttpMethod.Post, "/api/v1/auth/register", payload, ct).ConfigureAwait(false);
        if (!result.Success || result.Value is null)
            return OperationResult<AuthTokens>.Fail(result.Message, result.ErrorCode);

        var tokens = MapTokens(result.Value);
        AccessToken = tokens.AccessToken;
        await _tokens.SaveAsync(tokens, ct).ConfigureAwait(false);
        return OperationResult<AuthTokens>.Ok(tokens, "Account created and signed in.");
    }

    public async Task<OperationResult> LogoutAsync(CancellationToken ct = default)
    {
        if (IsConfigured)
        {
            try
            {
                await SendAsync<JsonElement>(HttpMethod.Post, "/api/v1/auth/logout", new { }, ct).ConfigureAwait(false);
            }
            catch
            {
                // Local sign-out must still happen even if the server is unreachable.
            }
        }

        AccessToken = null;
        await _tokens.ClearAsync(ct).ConfigureAwait(false);
        return OperationResult.Ok("Signed out locally.");
    }

    public async Task<OperationResult<ReputationVerdict>> CheckReputationAsync(string sha256, CancellationToken ct = default)
    {
        var notConfigured = CheckConfigured();
        if (notConfigured is not null)
            return OperationResult<ReputationVerdict>.Fail(notConfigured.Message, notConfigured.ErrorCode);

        if (!FileHashService.IsValidSha256(sha256))
            return OperationResult<ReputationVerdict>.Fail("A valid SHA-256 hash (64 hex characters) is required.", "INVALID_HASH");

        var payload = new { sha256 = sha256.ToLowerInvariant() };
        var result = await SendAsync<ReputationDto>(HttpMethod.Post, "/api/v1/reputation/check", payload, ct).ConfigureAwait(false);
        if (!result.Success || result.Value is null)
            return OperationResult<ReputationVerdict>.Fail(result.Message, result.ErrorCode);

        var dto = result.Value;
        return OperationResult<ReputationVerdict>.Ok(new ReputationVerdict
        {
            Sha256 = dto.Sha256,
            Verdict = dto.Verdict,
            Source = dto.Source,
            Detail = dto.Detail,
            CheckedAt = dto.CheckedAt
        }, $"Reputation verdict from {dto.Source}: {dto.Verdict}.");
    }

    public async Task<OperationResult<UpdateCheckResult>> CheckUpdatesAsync(string currentVersion, string channel = "stable", CancellationToken ct = default)
    {
        var notConfigured = CheckConfigured();
        if (notConfigured is not null)
            return OperationResult<UpdateCheckResult>.Fail(notConfigured.Message, notConfigured.ErrorCode);

        var path = $"/api/v1/updates/check?currentVersion={Uri.EscapeDataString(currentVersion)}&channel={Uri.EscapeDataString(channel)}";
        var result = await SendAsync<UpdateDto>(HttpMethod.Get, path, null, ct).ConfigureAwait(false);
        if (!result.Success || result.Value is null)
            return OperationResult<UpdateCheckResult>.Fail(result.Message, result.ErrorCode);

        var dto = result.Value;
        return OperationResult<UpdateCheckResult>.Ok(new UpdateCheckResult
        {
            CurrentVersion = dto.CurrentVersion,
            LatestVersion = dto.LatestVersion,
            UpdateAvailable = dto.UpdateAvailable,
            Channel = dto.Channel,
            ReleaseNotes = dto.ReleaseNotes,
            StoreUrl = dto.StoreUrl
        }, dto.UpdateAvailable ? $"Version {dto.LatestVersion} is available." : "No update available.");
    }

    public async Task<OperationResult<string>> GetCurrentUserEmailAsync(CancellationToken ct = default)
    {
        var notConfigured = CheckConfigured();
        if (notConfigured is not null)
            return OperationResult<string>.Fail(notConfigured.Message, notConfigured.ErrorCode);

        if (!IsAuthenticated)
            return OperationResult<string>.Fail("Not signed in.", "NOT_AUTHENTICATED");

        var result = await SendAsync<MeDto>(HttpMethod.Get, "/api/v1/auth/me", null, ct).ConfigureAwait(false);
        if (!result.Success || result.Value is null)
            return OperationResult<string>.Fail(result.Message, result.ErrorCode);

        return OperationResult<string>.Ok(result.Value.Email, "Signed-in account.");
    }

    /// <summary>Restore a persisted session (called at startup).</summary>
    public async Task RestoreSessionAsync(CancellationToken ct = default)
    {
        try
        {
            var stored = await _tokens.LoadAsync(ct).ConfigureAwait(false);
            if (stored is not null && stored.ExpiresAt > DateTimeOffset.UtcNow)
                AccessToken = stored.AccessToken;
        }
        catch
        {
            AccessToken = null;
        }
    }

    private OperationResult? CheckConfigured()
    {
        if (!IsConfigured)
        {
            return OperationResult.Fail(
                "Cloud API is not configured. Open Settings and enter the BECETTI SECURITY API URL to enable cloud features.",
                "NOT_CONFIGURED");
        }

        return null;
    }

    private static AuthTokens MapTokens(TokenDto dto) => new()
    {
        AccessToken = dto.AccessToken,
        RefreshToken = dto.RefreshToken,
        ExpiresAt = dto.ExpiresAt
    };

    private async Task<OperationResult<T>> SendAsync<T>(HttpMethod method, string path, object? body, CancellationToken ct)
    {
        using var timeoutCts = new CancellationTokenSource(RequestTimeout);
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct, timeoutCts.Token);

        try
        {
            using var request = new HttpRequestMessage(method, BaseUrl + path);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            if (!string.IsNullOrWhiteSpace(AccessToken))
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", AccessToken);

            if (body is not null)
                request.Content = JsonContent.Create(body);

            using var response = await _http.SendAsync(request, linkedCts.Token).ConfigureAwait(false);
            var responseBody = await response.Content.ReadAsStringAsync(linkedCts.Token).ConfigureAwait(false);

            if (response.StatusCode == HttpStatusCode.Unauthorized)
                return OperationResult<T>.Fail("The server rejected the session (401). Sign in again.", "UNAUTHORIZED");

            if (response.StatusCode == HttpStatusCode.TooManyRequests)
                return OperationResult<T>.Fail("The server rate-limited this request (429). Wait and retry.", "RATE_LIMITED");

            if (!response.IsSuccessStatusCode)
                return OperationResult<T>.Fail($"Server returned {(int)response.StatusCode} {response.StatusCode}: {Truncate(responseBody, 300)}", "SERVER_ERROR");

            if (string.IsNullOrWhiteSpace(responseBody))
                return OperationResult<T>.Fail("Server returned an empty response.", "EMPTY_RESPONSE");

            var parsed = JsonSerializer.Deserialize<T>(responseBody, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            if (parsed is null)
                return OperationResult<T>.Fail("Server returned an unreadable response.", "PARSE_ERROR");

            return OperationResult<T>.Ok(parsed);
        }
        catch (OperationCanceledException)
        {
            return OperationResult<T>.Fail("The request timed out. Check your internet connection.", "TIMEOUT");
        }
        catch (HttpRequestException ex)
        {
            return OperationResult<T>.Fail($"Could not reach the cloud API: {ex.Message}", "OFFLINE");
        }
        catch (Exception ex)
        {
            return OperationResult<T>.Fail($"Cloud request failed: {ex.Message}", "CLOUD_ERROR");
        }
    }

    private static string Truncate(string value, int maxLength) =>
        value.Length <= maxLength ? value : value.Substring(0, maxLength) + "...";

    private sealed class HealthDto
    {
        [JsonPropertyName("status")] public string Status { get; set; } = string.Empty;
        [JsonPropertyName("version")] public string Version { get; set; } = string.Empty;
        [JsonPropertyName("serverTime")] public DateTimeOffset ServerTime { get; set; }
    }

    private sealed class TokenDto
    {
        [JsonPropertyName("accessToken")] public string AccessToken { get; set; } = string.Empty;
        [JsonPropertyName("refreshToken")] public string RefreshToken { get; set; } = string.Empty;
        [JsonPropertyName("expiresAt")] public DateTimeOffset ExpiresAt { get; set; }
    }

    private sealed class ReputationDto
    {
        [JsonPropertyName("sha256")] public string Sha256 { get; set; } = string.Empty;
        [JsonPropertyName("verdict")] public string Verdict { get; set; } = "unknown";
        [JsonPropertyName("source")] public string Source { get; set; } = string.Empty;
        [JsonPropertyName("detail")] public string? Detail { get; set; }
        [JsonPropertyName("checkedAt")] public DateTimeOffset CheckedAt { get; set; }
    }

    private sealed class UpdateDto
    {
        [JsonPropertyName("currentVersion")] public string CurrentVersion { get; set; } = string.Empty;
        [JsonPropertyName("latestVersion")] public string? LatestVersion { get; set; }
        [JsonPropertyName("updateAvailable")] public bool UpdateAvailable { get; set; }
        [JsonPropertyName("channel")] public string Channel { get; set; } = "stable";
        [JsonPropertyName("releaseNotes")] public string? ReleaseNotes { get; set; }
        [JsonPropertyName("storeUrl")] public string? StoreUrl { get; set; }
    }

    private sealed class MeDto
    {
        [JsonPropertyName("email")] public string Email { get; set; } = string.Empty;
    }
}
