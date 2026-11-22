using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Text.Json;
using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

public interface IOutboundRadarService
{
    Task<OperationResult<OutboundRadarReport>> ScanLiveOutboundAsync(bool resolveGeoIp = true, CancellationToken ct = default);
    Task<OperationResult> BlockProcessExecutableAsync(string executablePath, CancellationToken ct = default);
}

/// <summary>
/// Live Outbound GeoIP Radar &amp; C2 Cross-Reference Engine:
/// reads active outbound TCP connections from Windows, resolves owning process paths,
/// checks every remote IP against local abuse.ch C2 Threat Feeds, enriches public IPs
/// with real Country / ASN Organization via cached ipwho.is lookup, and supports 1-click
/// Windows Firewall blocking via IPerAppFirewallService. Zero simulation.
/// </summary>
public sealed class OutboundRadarService : IOutboundRadarService
{
    private readonly INetworkMonitorService _network;
    private readonly IThreatFeedService _feeds;
    private readonly IPerAppFirewallService _firewall;
    private readonly HttpClient _http;
    private readonly ConcurrentDictionary<string, (string Country, string Org)> _geoCache = new(StringComparer.OrdinalIgnoreCase);

    public OutboundRadarService(
        INetworkMonitorService network,
        IThreatFeedService feeds,
        IPerAppFirewallService firewall,
        HttpClient http)
    {
        _network = network;
        _feeds = feeds;
        _firewall = firewall;
        _http = http;
    }

    public async Task<OperationResult<OutboundRadarReport>> ScanLiveOutboundAsync(bool resolveGeoIp = true, CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
            return OperationResult<OutboundRadarReport>.Fail("Live Outbound Radar requires Windows.", "UNSUPPORTED_OS");

        var connRes = await _network.GetActiveConnectionsAsync(ct).ConfigureAwait(false);
        if (!connRes.Success || connRes.Value is null)
            return OperationResult<OutboundRadarReport>.Fail(connRes.Message, connRes.ErrorCode);

        var externalConns = connRes.Value
            .Where(c => !string.IsNullOrWhiteSpace(c.RemoteAddress) && IsPublicIp(c.RemoteAddress!))
            .GroupBy(c => $"{c.OwningProcessId}|{c.RemoteAddress}|{c.RemotePort}")
            .Select(g => g.First())
            .Take(60)
            .ToList();

        // Resolve process executable paths locally
        var pidPathCache = new Dictionary<int, string>();
        foreach (var pid in externalConns.Select(c => c.OwningProcessId).Distinct())
        {
            if (pid <= 4) continue;
            try
            {
                using var p = Process.GetProcessById(pid);
                pidPathCache[pid] = p.MainModule?.FileName ?? string.Empty;
            }
            catch
            {
                pidPathCache[pid] = string.Empty;
            }
        }

        // Resolve GeoIP for up to 15 unique public IPs cleanly (cached thereafter)
        if (resolveGeoIp)
        {
            var uniqueIps = externalConns
                .Select(c => c.RemoteAddress!)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Where(ip => !_geoCache.ContainsKey(ip))
                .Take(15)
                .ToList();

            var geoTasks = uniqueIps.Select(ip => ResolveGeoIpAsync(ip, ct)).ToArray();
            await Task.WhenAll(geoTasks).ConfigureAwait(false);
        }

        var items = new List<OutboundConnectionIntel>();
        foreach (var c in externalConns)
        {
            var remoteIp = c.RemoteAddress!;
            var feedMatch = _feeds.CheckIp(remoteIp);
            var geo = _geoCache.TryGetValue(remoteIp, out var g)
                ? g
                : (Country: "Public IP", Org: "Lookup skipped/offline");

            items.Add(new OutboundConnectionIntel
            {
                ProcessId = c.OwningProcessId,
                ProcessName = string.IsNullOrWhiteSpace(c.ProcessName) ? $"PID {c.OwningProcessId}" : c.ProcessName!,
                ExecutablePath = pidPathCache.TryGetValue(c.OwningProcessId, out var path) ? path : string.Empty,
                RemoteIp = remoteIp,
                RemotePort = c.RemotePort,
                State = c.State,
                Country = geo.Country,
                Organization = geo.Org,
                IsThreatFeedMatch = feedMatch is not null,
                ThreatFeedSource = feedMatch?.FeedSource ?? string.Empty,
                MitreTag = feedMatch?.Mitre.TechniqueId ?? string.Empty
            });
        }

        var ordered = items
            .OrderByDescending(i => i.IsThreatFeedMatch)
            .ThenBy(i => i.ProcessName, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var countries = ordered
            .Select(i => i.Country)
            .Where(c => !string.IsNullOrWhiteSpace(c) && c != "Unknown" && c != "Public IP")
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Count();

        var report = new OutboundRadarReport
        {
            AuditedAt = DateTimeOffset.UtcNow,
            TotalExternalConnections = ordered.Count,
            UniqueCountries = countries,
            ThreatFeedMatches = ordered.Count(i => i.IsThreatFeedMatch),
            Connections = ordered
        };

        var msg = report.ThreatFeedMatches > 0
            ? $"CRITICAL: {report.ThreatFeedMatches} active connection(s) matched global abuse.ch Botnet C2 feeds!"
            : $"Live Radar: {report.TotalExternalConnections} active external connection(s) across {countries} country/region(s), 0 C2 matches.";

        return OperationResult<OutboundRadarReport>.Ok(report, msg);
    }

    public Task<OperationResult> BlockProcessExecutableAsync(string executablePath, CancellationToken ct = default) =>
        _firewall.BlockApplicationAsync(executablePath, ct);

    internal static bool IsPublicIp(string ipText)
    {
        if (!IPAddress.TryParse(ipText.Trim(), out var ip))
            return false;

        if (IPAddress.IsLoopback(ip) || ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any))
            return false;

        var bytes = ip.GetAddressBytes();
        if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork && bytes.Length == 4)
        {
            if (bytes[0] == 10) return false;
            if (bytes[0] == 127) return false;
            if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) return false;
            if (bytes[0] == 192 && bytes[1] == 168) return false;
            if (bytes[0] == 169 && bytes[1] == 254) return false;
            if (bytes[0] >= 224) return false;
            return true;
        }

        if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
        {
            if (ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal || ip.IsIPv6Multicast) return false;
            if ((bytes[0] & 0xFE) == 0xFC) return false; // fc00::/7 ULA
            return true;
        }

        return false;
    }

    private async Task ResolveGeoIpAsync(string ip, CancellationToken ct)
    {
        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, $"https://ipwho.is/{Uri.EscapeDataString(ip)}?fields=success,country,country_code,connection");
            req.Headers.TryAddWithoutValidation("User-Agent", "BECETTI-SECURITY/1.0");
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(4));

            using var resp = await _http.SendAsync(req, cts.Token).ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode) return;

            var json = await resp.Content.ReadAsStringAsync(cts.Token).ConfigureAwait(false);
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            if (root.TryGetProperty("success", out var okEl) && okEl.ValueKind == JsonValueKind.False)
                return;

            var country = root.TryGetProperty("country", out var cEl) ? cEl.GetString() ?? "Unknown" : "Unknown";
            var code = root.TryGetProperty("country_code", out var ccEl) ? ccEl.GetString() ?? "" : "";
            var org = "Unknown ASN";
            if (root.TryGetProperty("connection", out var connEl) && connEl.ValueKind == JsonValueKind.Object)
            {
                if (connEl.TryGetProperty("org", out var oEl) && !string.IsNullOrWhiteSpace(oEl.GetString()))
                    org = oEl.GetString()!;
                else if (connEl.TryGetProperty("isp", out var ispEl) && !string.IsNullOrWhiteSpace(ispEl.GetString()))
                    org = ispEl.GetString()!;
            }

            var countryLabel = string.IsNullOrWhiteSpace(code) ? country : $"{country} ({code})";
            _geoCache[ip] = (countryLabel, org);
        }
        catch
        {
            // Offline or rate-limited — leave uncached safely
        }
    }
}
