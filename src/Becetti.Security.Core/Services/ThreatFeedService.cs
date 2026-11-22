using System.Text.Json;
using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

public interface IThreatFeedService
{
    ThreatFeedStatus GetStatus();
    Task<OperationResult<ThreatFeedStatus>> SyncFeedsAsync(CancellationToken ct = default);
    ThreatFeedMatch? CheckIp(string ipAddress);
    ThreatFeedMatch? CheckDomainOrUrl(string hostOrUrl);
    ThreatFeedMatch? CheckSha256(string sha256Hex);
}

/// <summary>
/// Global Open Threat Intelligence Feeds Engine backed by official public abuse.ch feeds
/// (Feodo Tracker Botnet C2 IPs, URLhaus Active Malware Domains, MalwareBazaar Recent SHA-256 Hashes).
/// Zero API keys required, zero simulation — real daily global IOCs cached locally on disk.
/// </summary>
public sealed class ThreatFeedService : IThreatFeedService
{
    private const string FeodoIpFeedUrl = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt";
    private const string UrlhausFeedUrl = "https://urlhaus.abuse.ch/downloads/text_online/";
    private const string MalwareBazaarSha256Url = "https://bazaar.abuse.ch/export/txt/sha256/recent/";

    private readonly HttpClient _http;
    private readonly string _cacheDir;
    private readonly object _lock = new();

    private HashSet<string> _c2Ips = new(StringComparer.OrdinalIgnoreCase);
    private HashSet<string> _maliciousDomains = new(StringComparer.OrdinalIgnoreCase);
    private HashSet<string> _malwareHashes = new(StringComparer.OrdinalIgnoreCase);
    private List<string> _sourcesLoaded = new();
    private DateTimeOffset? _lastSyncedUtc;

    public ThreatFeedService(HttpClient http, ISettingsService settings)
    {
        _http = http;
        _cacheDir = Path.Combine(settings.DataDirectory, "threat-feeds");
        LoadCacheFromDisk();
    }

    public ThreatFeedStatus GetStatus()
    {
        lock (_lock)
        {
            return new ThreatFeedStatus
            {
                LastSyncedUtc = _lastSyncedUtc,
                BotnetC2IpCount = _c2Ips.Count,
                MaliciousDomainCount = _maliciousDomains.Count,
                MalwareSha256Count = _malwareHashes.Count,
                SourcesLoaded = _sourcesLoaded.ToList(),
                Summary = _lastSyncedUtc.HasValue
                    ? $"{_c2Ips.Count:N0} C2 IPs · {_maliciousDomains.Count:N0} malware domains · {_malwareHashes.Count:N0} SHA-256 hashes (synced {_lastSyncedUtc.Value.ToLocalTime():yyyy-MM-dd HH:mm})."
                    : "Global abuse.ch Threat Feeds not synced yet. Click 'Sync Global Feeds' to fetch live C2 IPs, malware domains & hashes."
            };
        }
    }

    public async Task<OperationResult<ThreatFeedStatus>> SyncFeedsAsync(CancellationToken ct = default)
    {
        var newIps = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var newDomains = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var newHashes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var sources = new List<string>();

        // 1. abuse.ch Feodo Tracker Recommended C2 IP Blocklist
        var feodoText = await DownloadFeedTextAsync(FeodoIpFeedUrl, ct).ConfigureAwait(false);
        if (!string.IsNullOrWhiteSpace(feodoText))
        {
            ParseFeodoIps(feodoText, newIps);
            if (newIps.Count > 0) sources.Add("abuse.ch Feodo Tracker (Botnet C2 IPs)");
        }

        // 2. abuse.ch URLhaus Active Malware Domains
        var urlhausText = await DownloadFeedTextAsync(UrlhausFeedUrl, ct).ConfigureAwait(false);
        if (!string.IsNullOrWhiteSpace(urlhausText))
        {
            ParseUrlhausDomains(urlhausText, newDomains);
            if (newDomains.Count > 0) sources.Add("abuse.ch URLhaus (Active Malware URLs)");
        }

        // 3. abuse.ch MalwareBazaar Recent SHA-256 Hashes
        var bazaarText = await DownloadFeedTextAsync(MalwareBazaarSha256Url, ct).ConfigureAwait(false);
        if (!string.IsNullOrWhiteSpace(bazaarText))
        {
            ParseSha256List(bazaarText, newHashes);
            if (newHashes.Count > 0) sources.Add("abuse.ch MalwareBazaar (Recent SHA-256)");
        }

        if (sources.Count == 0)
            return OperationResult<ThreatFeedStatus>.Fail("Could not reach abuse.ch public threat feeds. Check internet connection or firewall.", "FEED_SYNC_FAILED");

        lock (_lock)
        {
            if (newIps.Count > 0) _c2Ips = newIps;
            if (newDomains.Count > 0) _maliciousDomains = newDomains;
            if (newHashes.Count > 0) _malwareHashes = newHashes;
            _sourcesLoaded = sources;
            _lastSyncedUtc = DateTimeOffset.UtcNow;
        }

        SaveCacheToDisk();
        var status = GetStatus();
        return OperationResult<ThreatFeedStatus>.Ok(status, $"Synced {status.TotalIndicators:N0} global IOCs from {sources.Count} abuse.ch feed(s).");
    }

    public ThreatFeedMatch? CheckIp(string ipAddress)
    {
        if (string.IsNullOrWhiteSpace(ipAddress)) return null;
        var clean = ipAddress.Trim();
        lock (_lock)
        {
            if (_c2Ips.Contains(clean))
            {
                return new ThreatFeedMatch
                {
                    Indicator = clean,
                    IndicatorType = "IP",
                    FeedSource = "abuse.ch Feodo Tracker C2",
                    Context = "Active Botnet Command & Control (C2) IP address",
                    Mitre = MitreAttackMapper.GetById("T1071")
                };
            }
        }
        return null;
    }

    public ThreatFeedMatch? CheckDomainOrUrl(string hostOrUrl)
    {
        if (string.IsNullOrWhiteSpace(hostOrUrl)) return null;
        var host = ExtractHost(hostOrUrl);
        if (string.IsNullOrWhiteSpace(host)) return null;

        lock (_lock)
        {
            if (_maliciousDomains.Contains(host))
            {
                return new ThreatFeedMatch
                {
                    Indicator = host,
                    IndicatorType = "Domain",
                    FeedSource = "abuse.ch URLhaus",
                    Context = "Active malware distribution domain",
                    Mitre = MitreAttackMapper.GetById("T1105")
                };
            }
        }
        return null;
    }

    public ThreatFeedMatch? CheckSha256(string sha256Hex)
    {
        if (string.IsNullOrWhiteSpace(sha256Hex)) return null;
        var clean = sha256Hex.Trim().ToLowerInvariant();
        lock (_lock)
        {
            if (_malwareHashes.Contains(clean))
            {
                return new ThreatFeedMatch
                {
                    Indicator = clean,
                    IndicatorType = "SHA256",
                    FeedSource = "abuse.ch MalwareBazaar",
                    Context = "Known active malware sample SHA-256 hash",
                    Mitre = MitreAttackMapper.GetById("T1204.002")
                };
            }
        }
        return null;
    }

    internal static void ParseFeodoIps(string text, HashSet<string> target)
    {
        foreach (var raw in text.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line.StartsWith('#')) continue;
            if (System.Net.IPAddress.TryParse(line, out _))
                target.Add(line);
        }
    }

    internal static void ParseUrlhausDomains(string text, HashSet<string> target)
    {
        int cap = 25000;
        foreach (var raw in text.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
        {
            if (target.Count >= cap) break;
            var line = raw.Trim();
            if (line.Length == 0 || line.StartsWith('#')) continue;
            var host = ExtractHost(line);
            if (!string.IsNullOrWhiteSpace(host) && !System.Net.IPAddress.TryParse(host, out _))
                target.Add(host);
        }
    }

    internal static void ParseSha256List(string text, HashSet<string> target)
    {
        int cap = 15000;
        foreach (var raw in text.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
        {
            if (target.Count >= cap) break;
            var line = raw.Trim().ToLowerInvariant();
            if (line.Length == 64 && line.All(c => (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
                target.Add(line);
        }
    }

    internal static string ExtractHost(string input)
    {
        var trimmed = input.Trim();
        if (Uri.TryCreate(trimmed.Contains("://") ? trimmed : "https://" + trimmed, UriKind.Absolute, out var uri))
            return uri.Host.Trim().ToLowerInvariant();
        return string.Empty;
    }

    private async Task<string?> DownloadFeedTextAsync(string url, CancellationToken ct)
    {
        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, url);
            req.Headers.TryAddWithoutValidation("User-Agent", "BECETTI-SECURITY/1.0");
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(15));
            using var resp = await _http.SendAsync(req, cts.Token).ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode) return null;
            return await resp.Content.ReadAsStringAsync(cts.Token).ConfigureAwait(false);
        }
        catch
        {
            return null;
        }
    }

    private void SaveCacheToDisk()
    {
        try
        {
            Directory.CreateDirectory(_cacheDir);
            File.WriteAllLines(Path.Combine(_cacheDir, "c2-ips.txt"), _c2Ips);
            File.WriteAllLines(Path.Combine(_cacheDir, "domains.txt"), _maliciousDomains);
            File.WriteAllLines(Path.Combine(_cacheDir, "sha256.txt"), _malwareHashes);
            var meta = JsonSerializer.Serialize(new CacheMetadata
            {
                LastSyncedUtc = _lastSyncedUtc,
                Sources = _sourcesLoaded
            });
            File.WriteAllText(Path.Combine(_cacheDir, "meta.json"), meta);
        }
        catch { }
    }

    private void LoadCacheFromDisk()
    {
        try
        {
            var metaPath = Path.Combine(_cacheDir, "meta.json");
            if (!File.Exists(metaPath)) return;
            var meta = JsonSerializer.Deserialize<CacheMetadata>(File.ReadAllText(metaPath));
            if (meta is null) return;

            lock (_lock)
            {
                var ipFile = Path.Combine(_cacheDir, "c2-ips.txt");
                if (File.Exists(ipFile)) _c2Ips = new HashSet<string>(File.ReadAllLines(ipFile), StringComparer.OrdinalIgnoreCase);

                var domFile = Path.Combine(_cacheDir, "domains.txt");
                if (File.Exists(domFile)) _maliciousDomains = new HashSet<string>(File.ReadAllLines(domFile), StringComparer.OrdinalIgnoreCase);

                var hashFile = Path.Combine(_cacheDir, "sha256.txt");
                if (File.Exists(hashFile)) _malwareHashes = new HashSet<string>(File.ReadAllLines(hashFile), StringComparer.OrdinalIgnoreCase);

                _lastSyncedUtc = meta.LastSyncedUtc;
                _sourcesLoaded = meta.Sources ?? new List<string>();
            }
        }
        catch { }
    }

    private sealed class CacheMetadata
    {
        public DateTimeOffset? LastSyncedUtc { get; set; }
        public List<string>? Sources { get; set; }
    }
}
