using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Text.RegularExpressions;
using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

public interface IWifiArpGuardService
{
    Task<OperationResult<WifiArpAuditReport>> AuditAsync(CancellationToken ct = default);
}

/// <summary>
/// Real Wi-Fi Encryption &amp; ARP Spoofing / MITM Detector:
/// parses live `netsh wlan show interfaces` and `arp -a` + default gateway MAC tracking
/// to warn on Open/WEP/WPA-TKIP Wi-Fi networks, duplicate MAC addresses across different IPs,
/// or unexpected gateway MAC shifts (MITM / ARP poisoning). Zero simulation.
/// </summary>
public sealed class WifiArpGuardService : IWifiArpGuardService
{
    private string? _lastKnownGatewayIp;
    private string? _lastKnownGatewayMac;
    private readonly object _lock = new();

    private static readonly Regex ArpLineRegex = new(
        "^\\s*(\\d{1,3}(?:\\.\\d{1,3}){3})\\s+([0-9a-fA-F]{2}(?:[-:][0-9a-fA-F]{2}){5})\\s+(\\S+)",
        RegexOptions.Compiled);

    public async Task<OperationResult<WifiArpAuditReport>> AuditAsync(CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
            return OperationResult<WifiArpAuditReport>.Fail("Wi-Fi & ARP Guard requires Windows.", "UNSUPPORTED_OS");

        var wifiTask = ReadWifiSecurityAsync(ct);
        var arpTask = ReadArpTableRawAsync(ct);
        await Task.WhenAll(wifiTask, arpTask).ConfigureAwait(false);

        var wifi = wifiTask.Result;
        var gatewayIp = GetDefaultGatewayIp();
        var (entries, gatewayMac, alerts, spoofSuspected) = AnalyzeArpTable(arpTask.Result, gatewayIp);

        lock (_lock)
        {
            if (!string.IsNullOrWhiteSpace(gatewayIp) && !string.IsNullOrWhiteSpace(gatewayMac))
            {
                if (string.Equals(_lastKnownGatewayIp, gatewayIp, StringComparison.OrdinalIgnoreCase) &&
                    !string.IsNullOrWhiteSpace(_lastKnownGatewayMac) &&
                    !string.Equals(_lastKnownGatewayMac, gatewayMac, StringComparison.OrdinalIgnoreCase))
                {
                    spoofSuspected = true;
                    alerts.Insert(0, $"CRITICAL: Default Gateway ({gatewayIp}) MAC address changed from {_lastKnownGatewayMac} to {gatewayMac}! Possible ARP Spoofing / MITM attack.");
                }
                _lastKnownGatewayIp = gatewayIp;
                _lastKnownGatewayMac = gatewayMac;
            }
        }

        if (wifi.IsConnected && wifi.RiskLevel is "High" or "Critical")
            alerts.Add($"Wi-Fi Risk ({wifi.RiskLevel}): {wifi.RiskReason}");

        var report = new WifiArpAuditReport
        {
            AuditedAt = DateTimeOffset.UtcNow,
            Wifi = wifi,
            DefaultGatewayIp = gatewayIp,
            DefaultGatewayMac = gatewayMac,
            ArpSpoofingSuspected = spoofSuspected,
            Alerts = alerts,
            ArpEntries = entries
        };

        var msg = alerts.Count > 0
            ? $"Wi-Fi & ARP Audit flagged {alerts.Count} warning(s)."
            : $"Wi-Fi ({(wifi.IsConnected ? wifi.Ssid : "Ethernet/Disconnected")}) & ARP table ({entries.Count} entries) look clean.";

        return OperationResult<WifiArpAuditReport>.Ok(report, msg);
    }

    internal static WifiSecurityInfo ParseWlanInterfacesOutput(string output)
    {
        if (string.IsNullOrWhiteSpace(output))
            return new WifiSecurityInfo { IsConnected = false, RiskLevel = "Low", RiskReason = "No active Wi-Fi interface detected." };

        string GetField(string prefix)
        {
            foreach (var rawLine in output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
            {
                var line = rawLine.Trim();
                if (line.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                {
                    var idx = line.IndexOf(':');
                    if (idx > 0 && idx + 1 < line.Length)
                        return line[(idx + 1)..].Trim();
                }
            }
            return string.Empty;
        }

        var state = GetField("State");
        bool connected = state.Equals("connected", StringComparison.OrdinalIgnoreCase);
        if (!connected)
            return new WifiSecurityInfo { IsConnected = false, RiskLevel = "Low", RiskReason = "Not connected to a Wi-Fi network (wired Ethernet or Wi-Fi off)." };

        var iface = GetField("Name");
        var ssid = GetField("SSID");
        var bssid = GetField("AP BSSID");
        if (string.IsNullOrEmpty(bssid)) bssid = GetField("BSSID");
        var auth = GetField("Authentication");
        var cipher = GetField("Cipher");
        var radio = GetField("Radio type");
        var signal = GetField("Signal");

        string risk = "Low";
        string reason = $"Encrypted with {auth} / {cipher}.";

        if (auth.Contains("Open", StringComparison.OrdinalIgnoreCase) || cipher.Equals("None", StringComparison.OrdinalIgnoreCase))
        {
            risk = "Critical";
            reason = "UNENCRYPTED OPEN WI-FI! Traffic on this network can be sniffed in plaintext — use a VPN immediately.";
        }
        else if (auth.Contains("WEP", StringComparison.OrdinalIgnoreCase) || cipher.Contains("WEP", StringComparison.OrdinalIgnoreCase))
        {
            risk = "Critical";
            reason = "Broken WEP encryption detected (crackable in minutes).";
        }
        else if (cipher.Contains("TKIP", StringComparison.OrdinalIgnoreCase) ||
                 (auth.Contains("WPA-", StringComparison.OrdinalIgnoreCase) && !auth.Contains("WPA2", StringComparison.OrdinalIgnoreCase) && !auth.Contains("WPA3", StringComparison.OrdinalIgnoreCase)))
        {
            risk = "High";
            reason = "Legacy WPA / TKIP encryption detected — upgrade router to WPA2-AES or WPA3.";
        }
        else if (auth.Contains("WPA3", StringComparison.OrdinalIgnoreCase))
        {
            risk = "Low";
            reason = "Strong modern WPA3 wireless encryption active.";
        }

        return new WifiSecurityInfo
        {
            IsConnected = true,
            InterfaceName = iface,
            Ssid = ssid,
            Bssid = bssid,
            Authentication = auth,
            Cipher = cipher,
            RadioType = radio,
            SignalStrength = signal,
            RiskLevel = risk,
            RiskReason = reason
        };
    }

    internal static (List<ArpEntryInfo> Entries, string GatewayMac, List<string> Alerts, bool SpoofSuspected) AnalyzeArpTable(
        string arpOutput,
        string defaultGatewayIp)
    {
        var raw = new List<(string Ip, string Mac, string Type)>();
        foreach (var line in (arpOutput ?? string.Empty).Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
        {
            var m = ArpLineRegex.Match(line);
            if (!m.Success)
                continue;

            var ip = m.Groups[1].Value;
            var mac = m.Groups[2].Value.Replace(':', '-').ToLowerInvariant();
            var type = m.Groups[3].Value;

            // Ignore broadcast / multicast MACs (ff-ff-ff-ff-ff-ff, 01-00-5e-*, 33-33-*)
            if (mac == "ff-ff-ff-ff-ff-ff" || mac.StartsWith("01-00-5e-", StringComparison.Ordinal) || mac.StartsWith("33-33-", StringComparison.Ordinal))
                continue;
            // Ignore multicast IPv4 (224.0.0.0 - 239.255.255.255) & broadcast (.255)
            if (ip.EndsWith(".255", StringComparison.Ordinal) || ip.StartsWith("224.", StringComparison.Ordinal) || ip.StartsWith("239.", StringComparison.Ordinal))
                continue;

            raw.Add((ip, mac, type));
        }

        // Detect distinct unicast IPs sharing the same MAC (classic ARP spoofing signature)
        var macToIps = raw
            .Where(r => r.Type.Equals("dynamic", StringComparison.OrdinalIgnoreCase))
            .GroupBy(r => r.Mac, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.Select(x => x.Ip).Distinct().ToList(), StringComparer.OrdinalIgnoreCase);

        var duplicateMacs = macToIps
            .Where(kv => kv.Value.Count > 1)
            .ToDictionary(kv => kv.Key, kv => kv.Value, StringComparer.OrdinalIgnoreCase);

        var alerts = new List<string>();
        bool spoof = false;
        foreach (var dup in duplicateMacs)
        {
            spoof = true;
            var involvesGateway = !string.IsNullOrWhiteSpace(defaultGatewayIp) && dup.Value.Contains(defaultGatewayIp);
            var prefix = involvesGateway ? "CRITICAL (Gateway Involved)" : "WARNING";
            alerts.Add($"{prefix}: Duplicate MAC {dup.Key} claimed by multiple IPs ({string.Join(", ", dup.Value)}) — possible ARP spoofing / MITM.");
        }

        string gatewayMac = string.Empty;
        var entries = new List<ArpEntryInfo>();
        foreach (var r in raw)
        {
            bool isGw = !string.IsNullOrWhiteSpace(defaultGatewayIp) &&
                        r.Ip.Equals(defaultGatewayIp, StringComparison.OrdinalIgnoreCase);
            if (isGw && string.IsNullOrEmpty(gatewayMac))
                gatewayMac = r.Mac;

            entries.Add(new ArpEntryInfo
            {
                IpAddress = r.Ip,
                MacAddress = r.Mac,
                EntryType = r.Type,
                IsGateway = isGw,
                IsSuspiciousDuplicate = duplicateMacs.ContainsKey(r.Mac)
            });
        }

        return (entries, gatewayMac, alerts, spoof);
    }

    private static string GetDefaultGatewayIp()
    {
        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up)
                    continue;
                if (ni.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel)
                    continue;
                foreach (var gw in ni.GetIPProperties().GatewayAddresses)
                {
                    if (gw.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    {
                        var addr = gw.Address.ToString();
                        if (addr != "0.0.0.0")
                            return addr;
                    }
                }
            }
        }
        catch { }
        return string.Empty;
    }

    private static async Task<WifiSecurityInfo> ReadWifiSecurityAsync(CancellationToken ct)
    {
        try
        {
            var output = await RunCommandAsync("netsh.exe", "wlan show interfaces", ct).ConfigureAwait(false);
            return ParseWlanInterfacesOutput(output);
        }
        catch
        {
            return new WifiSecurityInfo { IsConnected = false, RiskLevel = "Low", RiskReason = "WLAN service not running or no Wi-Fi adapter." };
        }
    }

    private static async Task<string> ReadArpTableRawAsync(CancellationToken ct)
    {
        try { return await RunCommandAsync("arp.exe", "-a", ct).ConfigureAwait(false); }
        catch { return string.Empty; }
    }

    private static async Task<string> RunCommandAsync(string file, string args, CancellationToken ct)
    {
        var psi = new ProcessStartInfo
        {
            FileName = file,
            Arguments = args,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        using var proc = Process.Start(psi);
        if (proc is null)
            return string.Empty;
        var stdout = await proc.StandardOutput.ReadToEndAsync(ct).ConfigureAwait(false);
        await proc.WaitForExitAsync(ct).ConfigureAwait(false);
        return stdout;
    }
}
