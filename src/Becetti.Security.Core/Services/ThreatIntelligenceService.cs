using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

/// <summary>
/// HTTPS client for BECETTI SECURITY's VirusTotal proxy (a small server-side
/// relay that holds the real VirusTotal key; see /backend/becetti-ai in the
/// repo). This class never talks to VirusTotal directly and never contains a
/// key — only the backend's own public URL, which also serves BECETTI AI.
/// </summary>
public sealed class ThreatIntelligenceService : IThreatIntelligenceService
{
    private static readonly TimeSpan RequestTimeout = TimeSpan.FromSeconds(30);

    private readonly HttpClient _http;
    private readonly ISettingsService _settings;

    public ThreatIntelligenceService(HttpClient http, ISettingsService settings)
    {
        _http = http;
        _settings = settings;
    }

    public bool IsConfigured => !string.IsNullOrWhiteSpace(_settings.Current.AiApiBaseUrl);

    /// <summary>3 MB — matches the server-side cap in backend/becetti-ai/api/vt-file.js.</summary>
    public long MaxUploadBytes => 3L * 1024 * 1024;

    private string BaseUrl => _settings.Current.AiApiBaseUrl.TrimEnd('/');

    public async Task<OperationResult<ThreatIntelReport>> CheckFileHashAsync(string sha256, string? fileName, CancellationToken ct = default)
    {
        if (!FileHashService.IsValidSha256(sha256))
            return OperationResult<ThreatIntelReport>.Fail("That is not a valid SHA-256 hash.", "BAD_HASH");

        var payload = new { sha256 = sha256.ToLowerInvariant(), fileName };
        return await PostAsync("/api/vt-file", payload, ThreatIntelTargetType.File, ct).ConfigureAwait(false);
    }

    public async Task<OperationResult<ThreatIntelReport>> ScanFileAsync(string filePath, bool allowUpload, CancellationToken ct = default)
    {
        if (!IsConfigured)
            return NotConfigured();

        if (!File.Exists(filePath))
            return OperationResult<ThreatIntelReport>.Fail("File not found.", "FILE_NOT_FOUND");

        string sha256;
        try
        {
            sha256 = await FileHashService.ComputeSha256Async(filePath, ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            return OperationResult<ThreatIntelReport>.Fail($"Could not read the file: {ex.Message}", "HASH_FAILED");
        }

        var fileName = Path.GetFileName(filePath);

        // Step 1: hash-only lookup, same as CheckFileHashAsync — never uploads yet.
        var hashLookup = await PostAsync("/api/vt-file", new { sha256, fileName }, ThreatIntelTargetType.File, ct).ConfigureAwait(false);
        if (!hashLookup.Success)
            return hashLookup;

        if (hashLookup.Value!.Status != ThreatIntelStatus.NotFound)
            return hashLookup; // Found an existing real report — no upload needed.

        if (!allowUpload)
            return hashLookup; // Caller did not consent to uploading file content yet.

        FileInfo info;
        try
        {
            info = new FileInfo(filePath);
        }
        catch (Exception ex)
        {
            return OperationResult<ThreatIntelReport>.Fail($"Could not read the file: {ex.Message}", "FILE_READ_FAILED");
        }

        if (info.Length == 0)
            return OperationResult<ThreatIntelReport>.Fail("The file is empty.", "EMPTY_FILE");

        if (info.Length > MaxUploadBytes)
        {
            return OperationResult<ThreatIntelReport>.Fail(
                $"This file is {FormatBytes(info.Length)}, larger than the {FormatBytes(MaxUploadBytes)} this integration can upload for a fresh scan. " +
                "Only the SHA-256 hash lookup above is available for larger files.",
                "FILE_TOO_LARGE");
        }

        byte[] bytes;
        try
        {
            bytes = await File.ReadAllBytesAsync(filePath, ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            return OperationResult<ThreatIntelReport>.Fail($"Could not read the file: {ex.Message}", "FILE_READ_FAILED");
        }

        var fileBase64 = Convert.ToBase64String(bytes);
        return await PostAsync("/api/vt-file", new { sha256, fileName, fileBase64 }, ThreatIntelTargetType.File, ct).ConfigureAwait(false);
    }

    public async Task<OperationResult<ThreatIntelReport>> SubmitUrlAsync(string url, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(url) || !(url.StartsWith("http://", StringComparison.OrdinalIgnoreCase) || url.StartsWith("https://", StringComparison.OrdinalIgnoreCase)))
            return OperationResult<ThreatIntelReport>.Fail("Enter a valid http:// or https:// URL.", "BAD_URL");

        return await PostAsync("/api/vt-url", new { url }, ThreatIntelTargetType.Url, ct).ConfigureAwait(false);
    }

    public async Task<OperationResult<ThreatIntelReport>> GetAnalysisAsync(string analysisId, ThreatIntelTargetType targetType, CancellationToken ct = default)
    {
        if (!IsConfigured)
            return NotConfigured();

        if (string.IsNullOrWhiteSpace(analysisId))
            return OperationResult<ThreatIntelReport>.Fail("No analysis id to poll.", "BAD_REQUEST");

        using var timeoutCts = new CancellationTokenSource(RequestTimeout);
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct, timeoutCts.Token);

        try
        {
            var url = $"{BaseUrl}/api/vt-analysis?id={Uri.EscapeDataString(analysisId)}";
            using var response = await _http.GetAsync(url, linkedCts.Token).ConfigureAwait(false);
            return await HandleResponseAsync(response, targetType, linkedCts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return OperationResult<ThreatIntelReport>.Fail("The request to VirusTotal timed out. Check your internet connection.", "TIMEOUT");
        }
        catch (HttpRequestException ex)
        {
            return OperationResult<ThreatIntelReport>.Fail($"Could not reach the threat-intelligence service: {ex.Message}", "OFFLINE");
        }
        catch (Exception ex)
        {
            return OperationResult<ThreatIntelReport>.Fail($"VirusTotal request failed: {ex.Message}", "VT_ERROR");
        }
    }

    private OperationResult<ThreatIntelReport> NotConfigured() =>
        OperationResult<ThreatIntelReport>.Fail(
            "The threat-intelligence service is not configured. Open Settings and set the BECETTI server URL.",
            "NOT_CONFIGURED");

    private async Task<OperationResult<ThreatIntelReport>> PostAsync(string path, object payload, ThreatIntelTargetType targetType, CancellationToken ct)
    {
        if (!IsConfigured)
            return NotConfigured();

        using var timeoutCts = new CancellationTokenSource(RequestTimeout);
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct, timeoutCts.Token);

        try
        {
            using var response = await _http.PostAsJsonAsync(BaseUrl + path, payload, linkedCts.Token).ConfigureAwait(false);
            return await HandleResponseAsync(response, targetType, linkedCts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return OperationResult<ThreatIntelReport>.Fail("The request to VirusTotal timed out. Check your internet connection.", "TIMEOUT");
        }
        catch (HttpRequestException ex)
        {
            return OperationResult<ThreatIntelReport>.Fail($"Could not reach the threat-intelligence service: {ex.Message}", "OFFLINE");
        }
        catch (Exception ex)
        {
            return OperationResult<ThreatIntelReport>.Fail($"VirusTotal request failed: {ex.Message}", "VT_ERROR");
        }
    }

    private static async Task<OperationResult<ThreatIntelReport>> HandleResponseAsync(HttpResponseMessage response, ThreatIntelTargetType targetType, CancellationToken ct)
    {
        var body = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);

        if (response.StatusCode == HttpStatusCode.ServiceUnavailable)
            return OperationResult<ThreatIntelReport>.Fail("VirusTotal integration is not configured on the server yet (no key set up).", "NOT_CONFIGURED");

        if (response.StatusCode == HttpStatusCode.TooManyRequests)
        {
            var retryMsg = TryReadMessage(body) ?? "VirusTotal's rate limit was reached. Wait a moment and try again.";
            return OperationResult<ThreatIntelReport>.Fail(retryMsg, "RATE_LIMITED");
        }

        if (!response.IsSuccessStatusCode && response.StatusCode != HttpStatusCode.NotFound)
        {
            var errorMessage = TryReadMessage(body) ?? $"Server returned {(int)response.StatusCode} {response.StatusCode}.";
            return OperationResult<ThreatIntelReport>.Fail(errorMessage, "SERVER_ERROR");
        }

        if (string.IsNullOrWhiteSpace(body))
            return OperationResult<ThreatIntelReport>.Fail("The server returned an empty response.", "EMPTY_RESPONSE");

        try
        {
            using var doc = JsonDocument.Parse(body);
            var report = ParseReport(doc.RootElement, targetType);
            return OperationResult<ThreatIntelReport>.Ok(report, report.Message);
        }
        catch (Exception ex)
        {
            return OperationResult<ThreatIntelReport>.Fail($"Could not parse the server's response: {ex.Message}", "PARSE_ERROR");
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
    /// Maps the backend's normalized JSON (see backend/becetti-ai/api/_vtlib.js)
    /// into a ThreatIntelReport. Internal and static so unit tests can exercise
    /// this mapping against real sample response bodies without any HTTP call.
    /// </summary>
    internal static ThreatIntelReport ParseReport(JsonElement root, ThreatIntelTargetType fallbackTargetType)
    {
        string status = GetString(root, "status") ?? "unknown";
        string message = GetString(root, "message") ?? string.Empty;

        var parsedStatus = status switch
        {
            "completed" => ThreatIntelStatus.Completed,
            "queued" => ThreatIntelStatus.Queued,
            "in-progress" => ThreatIntelStatus.Queued,
            "not_found" => ThreatIntelStatus.NotFound,
            _ => ThreatIntelStatus.Unknown
        };

        var kind = GetString(root, "kind");
        var targetType = kind switch
        {
            "file" => ThreatIntelTargetType.File,
            "url" => ThreatIntelTargetType.Url,
            _ => fallbackTargetType
        };

        var sha256 = GetString(root, "sha256");
        var url = GetString(root, "url");
        var fileName = GetString(root, "fileName");
        var analysisId = GetString(root, "id");

        int malicious = 0, suspicious = 0, harmless = 0, undetected = 0, timeout = 0, total = 0;
        if (root.TryGetProperty("stats", out var stats) && stats.ValueKind == JsonValueKind.Object)
        {
            malicious = GetInt(stats, "malicious");
            suspicious = GetInt(stats, "suspicious");
            harmless = GetInt(stats, "harmless");
            undetected = GetInt(stats, "undetected");
            timeout = GetInt(stats, "timeout");
            total = GetInt(stats, "total");
        }

        var detectionRatio = GetString(root, "detectionRatio") ?? $"{malicious + suspicious}/{total}";

        var verdictText = GetString(root, "verdict");
        var verdict = verdictText switch
        {
            "malicious" => ThreatIntelVerdict.Malicious,
            "suspicious" => ThreatIntelVerdict.Suspicious,
            "clean" => ThreatIntelVerdict.Clean,
            _ => ThreatIntelVerdict.Unknown
        };

        var engines = new List<ThreatIntelEngineVerdict>();
        if (root.TryGetProperty("engines", out var enginesEl) && enginesEl.ValueKind == JsonValueKind.Array)
        {
            foreach (var e in enginesEl.EnumerateArray())
            {
                engines.Add(new ThreatIntelEngineVerdict
                {
                    EngineName = GetString(e, "name") ?? "Unknown engine",
                    Category = GetString(e, "category") ?? string.Empty,
                    Result = GetString(e, "result")
                });
            }
        }

        DateTimeOffset? scanDate = null;
        var scanDateText = GetString(root, "scanDateUtc");
        if (scanDateText is not null && DateTimeOffset.TryParse(scanDateText, out var parsedDate))
            scanDate = parsedDate;

        var permalink = GetString(root, "permalink");

        // Default, human-readable messages when the backend didn't already supply one
        // (e.g. a completed report has no "message" field in the backend's JSON).
        if (string.IsNullOrWhiteSpace(message))
        {
            message = parsedStatus switch
            {
                ThreatIntelStatus.Completed => $"VirusTotal scan complete: {detectionRatio} security vendors flagged this as a threat.",
                ThreatIntelStatus.Queued => "VirusTotal is scanning this now. Check back shortly.",
                ThreatIntelStatus.NotFound => "VirusTotal has no existing report for this.",
                _ => "VirusTotal returned an unrecognized status."
            };
        }

        return new ThreatIntelReport
        {
            Status = parsedStatus,
            TargetType = targetType,
            Verdict = verdict,
            AnalysisId = analysisId,
            Sha256 = sha256,
            Url = url,
            FileName = fileName,
            Malicious = malicious,
            Suspicious = suspicious,
            Harmless = harmless,
            Undetected = undetected,
            Timeout = timeout,
            TotalEngines = total,
            DetectionRatio = detectionRatio,
            FlaggedEngines = engines,
            ScanDateUtc = scanDate,
            Permalink = permalink,
            Message = message
        };
    }

    private static string? GetString(JsonElement el, string prop) =>
        el.TryGetProperty(prop, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    private static int GetInt(JsonElement el, string prop) =>
        el.TryGetProperty(prop, out var v) && v.ValueKind == JsonValueKind.Number ? v.GetInt32() : 0;

    private static string FormatBytes(long bytes) => bytes >= 1024 * 1024
        ? $"{bytes / (1024.0 * 1024.0):0.#} MB"
        : $"{bytes / 1024.0:0.#} KB";
}
