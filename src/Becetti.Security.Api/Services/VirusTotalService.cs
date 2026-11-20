using System.Net;
using System.Text.Json;

namespace Becetti.Security.Api.Services;

/// <summary>Result of an external reputation lookup.</summary>
public sealed record ProviderVerdict(string Verdict, string Source, string? Detail);

/// <summary>
/// VirusTotal file-reputation lookup. Returns null when no API key is
/// configured — the API then honestly reports "unknown / no provider
/// configured" instead of inventing a verdict.
/// </summary>
public sealed class VirusTotalService
{
    private readonly HttpClient _http;
    private readonly IConfiguration _configuration;
    private readonly ILogger<VirusTotalService> _logger;

    public VirusTotalService(HttpClient http, IConfiguration configuration, ILogger<VirusTotalService> logger)
    {
        _http = http;
        _configuration = configuration;
        _logger = logger;
    }

    public bool IsConfigured => !string.IsNullOrWhiteSpace(_configuration["VirusTotal:ApiKey"]);

    public async Task<ProviderVerdict?> CheckAsync(string sha256, CancellationToken ct = default)
    {
        var apiKey = _configuration["VirusTotal:ApiKey"];
        if (string.IsNullOrWhiteSpace(apiKey))
            return null;

        var baseUrl = (_configuration["VirusTotal:BaseUrl"] ?? "https://www.virustotal.com/api/v3").TrimEnd('/');

        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, $"{baseUrl}/files/{sha256.ToLowerInvariant()}");
            request.Headers.Add("x-apikey", apiKey);

            using var response = await _http.SendAsync(request, ct).ConfigureAwait(false);

            if (response.StatusCode == HttpStatusCode.NotFound)
                return new ProviderVerdict("unknown", "virustotal", "Hash not present in the VirusTotal database.");

            if (response.StatusCode == HttpStatusCode.TooManyRequests)
                return new ProviderVerdict("unknown", "virustotal", "VirusTotal rate limit reached; verdict unavailable.");

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("VirusTotal lookup failed with status {Status}", response.StatusCode);
                return new ProviderVerdict("unknown", "virustotal", $"VirusTotal returned {(int)response.StatusCode}.");
            }

            var body = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            using var doc = JsonDocument.Parse(body);

            if (!doc.RootElement.TryGetProperty("data", out var data) ||
                !data.TryGetProperty("attributes", out var attributes) ||
                !attributes.TryGetProperty("last_analysis_stats", out var stats))
            {
                return new ProviderVerdict("unknown", "virustotal", "VirusTotal response did not contain analysis stats.");
            }

            var malicious = GetStat(stats, "malicious");
            var suspicious = GetStat(stats, "suspicious");
            var harmless = GetStat(stats, "harmless");
            var undetected = GetStat(stats, "undetected");

            var verdict = malicious > 0 ? "malicious"
                : suspicious > 0 ? "suspicious"
                : "clean";

            var detail = $"VirusTotal engines: {malicious} malicious, {suspicious} suspicious, {harmless} harmless, {undetected} undetected.";
            return new ProviderVerdict(verdict, "virustotal", detail);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "VirusTotal lookup errored");
            return new ProviderVerdict("unknown", "virustotal", $"VirusTotal lookup failed: {ex.Message}");
        }
    }

    private static int GetStat(JsonElement stats, string name)
    {
        if (stats.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.Number && value.TryGetInt32(out var n))
            return n;
        return 0;
    }
}
