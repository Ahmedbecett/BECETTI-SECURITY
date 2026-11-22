using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

/// <summary>
/// HTTPS client for BECETTI SECURITY's data-breach monitoring proxy (a small
/// server-side relay; see /backend/becetti-ai in the repo). This class never
/// talks to XposedOrNot or HIBP directly and never contains a key — both
/// upstream services are free and keyless, and the proxy exists purely to
/// keep every outbound network call on one auditable path, matching the
/// VirusTotal integration's architecture.
/// </summary>
public sealed class DataBreachService : IDataBreachService
{
    private static readonly TimeSpan RequestTimeout = TimeSpan.FromSeconds(20);

    private readonly HttpClient _http;
    private readonly ISettingsService _settings;

    public DataBreachService(HttpClient http, ISettingsService settings)
    {
        _http = http;
        _settings = settings;
    }

    public bool IsConfigured => !string.IsNullOrWhiteSpace(_settings.Current.AiApiBaseUrl);

    private string BaseUrl => _settings.Current.AiApiBaseUrl.TrimEnd('/');

    public async Task<OperationResult<EmailBreachReport>> CheckEmailAsync(string email, CancellationToken ct = default)
    {
        if (!IsConfigured)
            return OperationResult<EmailBreachReport>.Fail(
                "The data-breach monitoring service is not configured. Open Settings and set the BECETTI server URL.",
                "NOT_CONFIGURED");

        email = (email ?? string.Empty).Trim();
        if (!IsValidEmail(email))
            return OperationResult<EmailBreachReport>.Fail("Enter a valid email address.", "BAD_EMAIL");

        using var timeoutCts = new CancellationTokenSource(RequestTimeout);
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct, timeoutCts.Token);

        try
        {
            var url = $"{BaseUrl}/api/breach-email?email={Uri.EscapeDataString(email)}";
            using var response = await _http.GetAsync(url, linkedCts.Token).ConfigureAwait(false);
            var body = await response.Content.ReadAsStringAsync(linkedCts.Token).ConfigureAwait(false);

            if (response.StatusCode == HttpStatusCode.TooManyRequests)
                return OperationResult<EmailBreachReport>.Fail(TryReadMessage(body) ?? "The breach-lookup service's rate limit was reached. Wait a bit and try again.", "RATE_LIMITED");

            if (!response.IsSuccessStatusCode)
                return OperationResult<EmailBreachReport>.Fail(TryReadMessage(body) ?? $"Server returned {(int)response.StatusCode} {response.StatusCode}.", "SERVER_ERROR");

            if (string.IsNullOrWhiteSpace(body))
                return OperationResult<EmailBreachReport>.Fail("The server returned an empty response.", "EMPTY_RESPONSE");

            using var doc = JsonDocument.Parse(body);
            var report = ParseEmailReport(doc.RootElement);
            return OperationResult<EmailBreachReport>.Ok(report, report.Message);
        }
        catch (OperationCanceledException)
        {
            return OperationResult<EmailBreachReport>.Fail("The request timed out. Check your internet connection.", "TIMEOUT");
        }
        catch (HttpRequestException ex)
        {
            return OperationResult<EmailBreachReport>.Fail($"Could not reach the data-breach monitoring service: {ex.Message}", "OFFLINE");
        }
        catch (Exception ex)
        {
            return OperationResult<EmailBreachReport>.Fail($"Email breach check failed: {ex.Message}", "ERROR");
        }
    }

    public async Task<OperationResult<PasswordBreachReport>> CheckPasswordAsync(string password, CancellationToken ct = default)
    {
        if (!IsConfigured)
            return OperationResult<PasswordBreachReport>.Fail(
                "The data-breach monitoring service is not configured. Open Settings and set the BECETTI server URL.",
                "NOT_CONFIGURED");

        if (string.IsNullOrEmpty(password))
            return OperationResult<PasswordBreachReport>.Fail("Enter a password to check.", "BAD_REQUEST");

        // k-anonymity model: hash locally, send only the first 5 hex characters.
        // The full hash — and certainly the password itself — never leaves this process.
        var fullHash = Sha1Hex(password);
        var prefix = fullHash[..5];
        var suffix = fullHash[5..];

        using var timeoutCts = new CancellationTokenSource(RequestTimeout);
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct, timeoutCts.Token);

        try
        {
            var url = $"{BaseUrl}/api/breach-password?prefix={prefix}";
            using var response = await _http.GetAsync(url, linkedCts.Token).ConfigureAwait(false);
            var body = await response.Content.ReadAsStringAsync(linkedCts.Token).ConfigureAwait(false);

            if (response.StatusCode == HttpStatusCode.TooManyRequests)
                return OperationResult<PasswordBreachReport>.Fail(TryReadMessage(body) ?? "The password-exposure service's rate limit was reached. Wait a bit and try again.", "RATE_LIMITED");

            if (!response.IsSuccessStatusCode)
                return OperationResult<PasswordBreachReport>.Fail(TryReadMessage(body) ?? $"Server returned {(int)response.StatusCode} {response.StatusCode}.", "SERVER_ERROR");

            if (string.IsNullOrWhiteSpace(body))
                return OperationResult<PasswordBreachReport>.Fail("The server returned an empty response.", "EMPTY_RESPONSE");

            using var doc = JsonDocument.Parse(body);
            if (!doc.RootElement.TryGetProperty("suffixes", out var suffixesEl) || suffixesEl.ValueKind != JsonValueKind.String)
                return OperationResult<PasswordBreachReport>.Fail("Could not parse the server's response.", "PARSE_ERROR");

            var report = ParsePasswordRangeResponse(suffixesEl.GetString() ?? string.Empty, suffix);
            return OperationResult<PasswordBreachReport>.Ok(report, report.Message);
        }
        catch (OperationCanceledException)
        {
            return OperationResult<PasswordBreachReport>.Fail("The request timed out. Check your internet connection.", "TIMEOUT");
        }
        catch (HttpRequestException ex)
        {
            return OperationResult<PasswordBreachReport>.Fail($"Could not reach the data-breach monitoring service: {ex.Message}", "OFFLINE");
        }
        catch (Exception ex)
        {
            return OperationResult<PasswordBreachReport>.Fail($"Password exposure check failed: {ex.Message}", "ERROR");
        }
    }

    private static string Sha1Hex(string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        var hash = SHA1.HashData(bytes);
        return Convert.ToHexString(hash); // uppercase hex, matches HIBP's range API convention
    }

    private static bool IsValidEmail(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 320)
            return false;
        var at = value.IndexOf('@');
        return at > 0 && at < value.Length - 1 && value.IndexOf('.', at) > at;
    }

    private static string? TryReadMessage(string body)
    {
        try
        {
            using var doc = JsonDocument.Parse(body);
            if (doc.RootElement.TryGetProperty("message", out var m) && m.ValueKind == JsonValueKind.String)
                return m.GetString();
        }
        catch
        {
            // ignore
        }
        return null;
    }

    /// <summary>
    /// Maps the backend's normalized JSON (see backend/becetti-ai/api/_breachlib.js)
    /// into an EmailBreachReport. Internal and static so unit tests can exercise
    /// this mapping against real sample response bodies without any HTTP call.
    /// </summary>
    internal static EmailBreachReport ParseEmailReport(JsonElement root)
    {
        var email = GetString(root, "email") ?? string.Empty;
        var breached = root.TryGetProperty("breached", out var b) && b.ValueKind == JsonValueKind.True;
        var breachCount = GetInt(root, "breachCount");
        var message = GetString(root, "message") ?? string.Empty;
        var riskLabel = GetString(root, "riskLabel");
        int? riskScore = root.TryGetProperty("riskScore", out var rs) && rs.ValueKind == JsonValueKind.Number ? rs.GetInt32() : null;

        var breaches = new List<DataBreachRecord>();
        if (root.TryGetProperty("breaches", out var breachesEl) && breachesEl.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in breachesEl.EnumerateArray())
            {
                var exposedData = new List<string>();
                if (item.TryGetProperty("exposedData", out var expEl) && expEl.ValueKind == JsonValueKind.Array)
                {
                    foreach (var e in expEl.EnumerateArray())
                        if (e.ValueKind == JsonValueKind.String && e.GetString() is { } s)
                            exposedData.Add(s);
                }

                breaches.Add(new DataBreachRecord
                {
                    Name = GetString(item, "name") ?? "Unknown",
                    Domain = GetString(item, "domain"),
                    Industry = GetString(item, "industry"),
                    Description = GetString(item, "description"),
                    ExposedData = exposedData,
                    BreachDate = GetString(item, "breachDate"),
                    RecordsExposed = item.TryGetProperty("recordsExposed", out var re) && re.ValueKind == JsonValueKind.Number ? re.GetInt64() : null,
                    PasswordRisk = GetString(item, "passwordRisk"),
                    Verified = item.TryGetProperty("verified", out var v) && v.ValueKind == JsonValueKind.True,
                    ReferenceUrl = GetString(item, "referenceUrl")
                });
            }
        }

        if (string.IsNullOrWhiteSpace(message))
        {
            message = breached
                ? $"Found in {breachCount} known data breach{(breachCount == 1 ? "" : "es")}."
                : "No known public data breach contains this email address.";
        }

        return new EmailBreachReport
        {
            Email = email,
            Breached = breached,
            BreachCount = breachCount,
            Breaches = breaches,
            RiskLabel = riskLabel,
            RiskScore = riskScore,
            Message = message
        };
    }

    /// <summary>
    /// Matches a target SHA-1 suffix against HIBP's real "SUFFIX:COUNT" range
    /// response (one pair per line, CRLF-separated). Internal and static so
    /// unit tests can exercise this against real sample response bodies
    /// without any HTTP call. Padding entries HIBP adds for traffic-analysis
    /// resistance simply never match the real target suffix.
    /// </summary>
    internal static PasswordBreachReport ParsePasswordRangeResponse(string suffixesText, string targetSuffix)
    {
        var lines = suffixesText.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        foreach (var line in lines)
        {
            var parts = line.Split(':', 2);
            if (parts.Length != 2)
                continue;

            if (string.Equals(parts[0].Trim(), targetSuffix, StringComparison.OrdinalIgnoreCase))
            {
                var count = long.TryParse(parts[1].Trim(), out var c) ? c : 0;
                return new PasswordBreachReport
                {
                    Breached = true,
                    TimesSeen = count,
                    Message = $"This password has been seen {count:N0} time{(count == 1 ? "" : "s")} in known data breaches. Change it immediately."
                };
            }
        }

        return new PasswordBreachReport
        {
            Breached = false,
            TimesSeen = 0,
            Message = "This password was not found in any known data breach."
        };
    }

    private static string? GetString(JsonElement el, string prop) =>
        el.TryGetProperty(prop, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    private static int GetInt(JsonElement el, string prop) =>
        el.TryGetProperty(prop, out var v) && v.ValueKind == JsonValueKind.Number ? v.GetInt32() : 0;
}
