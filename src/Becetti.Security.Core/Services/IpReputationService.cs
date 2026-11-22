using System.Net;
using System.Text.Json;
using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

/// <summary>
/// HTTPS client for BECETTI SECURITY's AbuseIPDB proxy (a small server-side
/// relay that holds the real AbuseIPDB key; see /backend/becetti-ai in the
/// repo). This class never talks to AbuseIPDB directly and never contains a
/// key — only the backend's own public URL.
/// </summary>
public sealed class IpReputationService : IIpReputationService
{
    private static readonly TimeSpan RequestTimeout = TimeSpan.FromSeconds(30);

    private readonly HttpClient _http;
    private readonly ISettingsService _settings;

    public IpReputationService(HttpClient http, ISettingsService settings)
    {
        _http = http;
        _settings = settings;
    }

    public bool IsConfigured => !string.IsNullOrWhiteSpace(_settings.Current.AiApiBaseUrl);

    private string BaseUrl => _settings.Current.AiApiBaseUrl.TrimEnd('/');

    public async Task<OperationResult<IpReputationReport>> CheckIpAsync(string ipAddress, CancellationToken ct = default)
    {
        ipAddress = (ipAddress ?? string.Empty).Trim();
        if (string.IsNullOrWhiteSpace(ipAddress) || !System.Net.IPAddress.TryParse(ipAddress, out _))
            return OperationResult<IpReputationReport>.Fail("Enter a valid IPv4 or IPv6 address.", "BAD_IP");

        if (!IsConfigured)
            return OperationResult<IpReputationReport>.Fail(
                "The IP reputation service is not configured. Open Settings and set the BECETTI server URL.",
                "NOT_CONFIGURED");

        using var timeoutCts = new CancellationTokenSource(RequestTimeout);
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct, timeoutCts.Token);

        try
        {
            var url = $"{BaseUrl}/api/abuseipdb-check?ip={Uri.EscapeDataString(ipAddress)}";
            using var response = await _http.GetAsync(url, linkedCts.Token).ConfigureAwait(false);
            var body = await response.Content.ReadAsStringAsync(linkedCts.Token).ConfigureAwait(false);

            if (response.StatusCode == HttpStatusCode.ServiceUnavailable)
                return OperationResult<IpReputationReport>.Fail("IP reputation lookups are not configured on the server yet (no AbuseIPDB key set up).", "NOT_CONFIGURED");

            if (response.StatusCode == HttpStatusCode.TooManyRequests)
            {
                var retryMsg = TryReadMessage(body) ?? "AbuseIPDB's free-tier daily quota was reached. Wait and try again.";
                return OperationResult<IpReputationReport>.Fail(retryMsg, "RATE_LIMITED");
            }

            if (response.StatusCode == HttpStatusCode.BadRequest)
            {
                var badRequestMsg = TryReadMessage(body) ?? "AbuseIPDB rejected that IP address.";
                return OperationResult<IpReputationReport>.Fail(badRequestMsg, "BAD_REQUEST");
            }

            if (!response.IsSuccessStatusCode)
            {
                var errorMessage = TryReadMessage(body) ?? $"Server returned {(int)response.StatusCode} {response.StatusCode}.";
                return OperationResult<IpReputationReport>.Fail(errorMessage, "SERVER_ERROR");
            }

            if (string.IsNullOrWhiteSpace(body))
                return OperationResult<IpReputationReport>.Fail("The server returned an empty response.", "EMPTY_RESPONSE");

            using var doc = JsonDocument.Parse(body);
            var report = ParseReport(doc.RootElement);
            return OperationResult<IpReputationReport>.Ok(report, report.Message);
        }
        catch (OperationCanceledException)
        {
            return OperationResult<IpReputationReport>.Fail("The request to AbuseIPDB timed out. Check your internet connection.", "TIMEOUT");
        }
        catch (HttpRequestException ex)
        {
            return OperationResult<IpReputationReport>.Fail($"Could not reach the IP reputation service: {ex.Message}", "OFFLINE");
        }
        catch (Exception ex)
        {
            return OperationResult<IpReputationReport>.Fail($"AbuseIPDB request failed: {ex.Message}", "ERROR");
        }
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
    /// Maps the backend's normalized JSON (see backend/becetti-ai/api/_abuseipdblib.js)
    /// into an IpReputationReport. Internal and static so unit tests can exercise this
    /// mapping against real sample response bodies without any HTTP call.
    /// </summary>
    internal static IpReputationReport ParseReport(JsonElement root)
    {
        var ipAddress = GetString(root, "ipAddress") ?? string.Empty;
        var abuseConfidenceScore = GetInt(root, "abuseConfidenceScore");
        var totalReports = GetInt(root, "totalReports");
        var numDistinctUsers = GetInt(root, "numDistinctUsers");

        var verdictText = GetString(root, "verdict");
        var verdict = verdictText switch
        {
            "malicious" => IpReputationVerdict.Malicious,
            "suspicious" => IpReputationVerdict.Suspicious,
            "clean" => IpReputationVerdict.Clean,
            _ => IpReputationVerdict.Unknown
        };

        DateTimeOffset? lastReported = null;
        var lastReportedText = GetString(root, "lastReportedAtUtc");
        if (lastReportedText is not null && DateTimeOffset.TryParse(lastReportedText, out var parsedDate))
            lastReported = parsedDate;

        var message = verdict switch
        {
            IpReputationVerdict.Malicious => $"AbuseIPDB reports this address as malicious: {abuseConfidenceScore}% abuse confidence from {totalReports} report(s).",
            IpReputationVerdict.Suspicious => $"AbuseIPDB flags this address as suspicious: {abuseConfidenceScore}% abuse confidence from {totalReports} report(s).",
            IpReputationVerdict.Clean => totalReports > 0
                ? $"AbuseIPDB has {totalReports} old/low-confidence report(s) for this address but does not consider it currently abusive ({abuseConfidenceScore}%)."
                : "AbuseIPDB has no abuse reports for this address.",
            _ => "AbuseIPDB returned an unrecognized result."
        };

        return new IpReputationReport
        {
            IpAddress = ipAddress,
            IsPublic = GetBool(root, "isPublic"),
            IpVersion = root.TryGetProperty("ipVersion", out var v) && v.ValueKind == JsonValueKind.Number ? v.GetInt32() : null,
            AbuseConfidenceScore = abuseConfidenceScore,
            TotalReports = totalReports,
            NumDistinctUsers = numDistinctUsers,
            LastReportedAtUtc = lastReported,
            CountryCode = GetString(root, "countryCode"),
            CountryName = GetString(root, "countryName"),
            UsageType = GetString(root, "usageType"),
            Isp = GetString(root, "isp"),
            Domain = GetString(root, "domain"),
            IsTor = GetBool(root, "isTor") ?? false,
            IsWhitelisted = GetBool(root, "isWhitelisted") ?? false,
            Verdict = verdict,
            Message = message
        };
    }

    private static string? GetString(JsonElement el, string prop) =>
        el.TryGetProperty(prop, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    private static int GetInt(JsonElement el, string prop) =>
        el.TryGetProperty(prop, out var v) && v.ValueKind == JsonValueKind.Number ? v.GetInt32() : 0;

    private static bool? GetBool(JsonElement el, string prop) =>
        el.TryGetProperty(prop, out var v) && (v.ValueKind == JsonValueKind.True || v.ValueKind == JsonValueKind.False) ? v.GetBoolean() : null;
}
