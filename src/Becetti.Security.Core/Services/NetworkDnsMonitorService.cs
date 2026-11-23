using System.Diagnostics;
using System.Text.Json;
using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

public interface INetworkDnsMonitorService
{
    Task<OperationResult<DnsAndAppNetworkReport>> AuditDnsCacheAndAppsAsync(CancellationToken ct = default);
}

/// <summary>
/// #10: Live DNS Cache Threat Logger &amp; Per-App Connection Auditor.
/// Reads real Windows DNS Client Cache (Get-DnsClientCache) and cross-references EVERY domain
/// against live abuse.ch URLhaus malware domains, plus summarizes active TCP connections and
/// memory footprint per application process. Zero simulation.
/// </summary>
public sealed class NetworkDnsMonitorService : INetworkDnsMonitorService
{
    private readonly INetworkMonitorService _network;
    private readonly IThreatFeedService _feeds;

    public NetworkDnsMonitorService(INetworkMonitorService network, IThreatFeedService feeds)
    {
        _network = network;
        _feeds = feeds;
    }

    public async Task<OperationResult<DnsAndAppNetworkReport>> AuditDnsCacheAndAppsAsync(CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
            return OperationResult<DnsAndAppNetworkReport>.Fail("DNS Cache & App Network Auditor requires Windows.", "UNSUPPORTED_OS");

        var dnsJson = await RunPowerShellAsync(
            "Get-DnsClientCache | Select-Object Entry,Data,TimeToLive | ConvertTo-Json -Compress", ct).ConfigureAwait(false);
        var dnsEntries = ParseDnsCacheJson(dnsJson, _feeds);

        var connRes = await _network.GetActiveConnectionsAsync(ct).ConfigureAwait(false);
        var appSummaries = BuildPerAppSummary(connRes.Success && connRes.Value is not null ? connRes.Value : Array.Empty<NetworkConnectionInfo>());

        int badDns = dnsEntries.Count(d => d.IsMalicious);
        var summary = badDns > 0
            ? $"CRITICAL: {badDns} cached DNS domain(s) matched abuse.ch URLhaus malware feeds! ({dnsEntries.Count} DNS entries, {appSummaries.Count} active apps)"
            : $"DNS & App Audit Clean: {dnsEntries.Count} live DNS cache entries (0 malware matches) across {appSummaries.Count} networking app(s).";

        return OperationResult<DnsAndAppNetworkReport>.Ok(new DnsAndAppNetworkReport
        {
            CapturedAt = DateTimeOffset.UtcNow,
            MaliciousDnsCount = badDns,
            DnsEntries = dnsEntries,
            AppSummaries = appSummaries,
            Summary = summary
        }, summary);
    }

    internal static List<DnsCacheEntryIntel> ParseDnsCacheJson(string json, IThreatFeedService feeds)
    {
        var list = new List<DnsCacheEntryIntel>();
        if (string.IsNullOrWhiteSpace(json)) return list;

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            if (root.ValueKind == JsonValueKind.Array)
            {
                foreach (var el in root.EnumerateArray())
                    AddDnsEntry(el, feeds, seen, list);
            }
            else if (root.ValueKind == JsonValueKind.Object)
            {
                AddDnsEntry(root, feeds, seen, list);
            }
        }
        catch { }

        return list
            .OrderByDescending(d => d.IsMalicious)
            .ThenBy(d => d.Domain, StringComparer.OrdinalIgnoreCase)
            .Take(120)
            .ToList();
    }

    private static void AddDnsEntry(JsonElement el, IThreatFeedService feeds, HashSet<string> seen, List<DnsCacheEntryIntel> list)
    {
        string domain = el.TryGetProperty("Entry", out var eEl) ? eEl.GetString() ?? "" : "";
        string data = el.TryGetProperty("Data", out var dEl) ? dEl.GetString() ?? "" : "";
        int ttl = el.TryGetProperty("TimeToLive", out var tEl) && tEl.TryGetInt32(out var tv) ? tv : 0;

        if (string.IsNullOrWhiteSpace(domain) || !seen.Add($"{domain}|{data}")) return;

        var hit = feeds.CheckDomainOrUrl(domain) ?? feeds.CheckIp(data);
        list.Add(new DnsCacheEntryIntel
        {
            Domain = domain,
            ResolvedData = string.IsNullOrWhiteSpace(data) ? "(cached)" : data,
            TtlSeconds = ttl,
            IsMalicious = hit is not null,
            ThreatSource = hit?.FeedSource ?? string.Empty,
            MitreTag = hit?.Mitre.TechniqueId ?? string.Empty
        });
    }

    private static List<AppNetworkUsageSummary> BuildPerAppSummary(IReadOnlyList<NetworkConnectionInfo> conns)
    {
        var groups = conns.GroupBy(c => c.OwningProcessId);
        var list = new List<AppNetworkUsageSummary>();

        foreach (var g in groups)
        {
            int pid = g.Key;
            var all = g.ToList();
            int ext = all.Count(c => !string.IsNullOrWhiteSpace(c.RemoteAddress) && OutboundRadarService.IsPublicIp(c.RemoteAddress!));
            string pname = all.FirstOrDefault(c => !string.IsNullOrWhiteSpace(c.ProcessName))?.ProcessName ?? $"PID {pid}";
            string exePath = string.Empty;
            double memMb = 0;

            if (pid > 4)
            {
                try
                {
                    using var proc = Process.GetProcessById(pid);
                    pname = proc.ProcessName;
                    memMb = Math.Round(proc.WorkingSet64 / (1024.0 * 1024.0), 1);
                    exePath = proc.MainModule?.FileName ?? string.Empty;
                }
                catch { }
            }

            var topEndpoints = string.Join(", ",
                all.Where(c => !string.IsNullOrWhiteSpace(c.RemoteAddress) && OutboundRadarService.IsPublicIp(c.RemoteAddress!))
                   .Select(c => $"{c.RemoteAddress}:{c.RemotePort}")
                   .Distinct()
                   .Take(3));

            list.Add(new AppNetworkUsageSummary
            {
                ProcessId = pid,
                ProcessName = pname,
                ExecutablePath = exePath,
                ActiveConnections = all.Count,
                ExternalConnections = ext,
                WorkingSetMb = memMb,
                TopRemoteEndpoints = string.IsNullOrWhiteSpace(topEndpoints) ? "Local / Listening" : topEndpoints
            });
        }

        return list.OrderByDescending(a => a.ExternalConnections).ThenByDescending(a => a.ActiveConnections).Take(50).ToList();
    }

    private static async Task<string> RunPowerShellAsync(string command, CancellationToken ct)
    {
        try
        {
            using var p = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"{command}\"",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                }
            };
            p.Start();
            var output = await p.StandardOutput.ReadToEndAsync(ct).ConfigureAwait(false);
            await p.WaitForExitAsync(ct).ConfigureAwait(false);
            return output;
        }
        catch { return string.Empty; }
    }
}
