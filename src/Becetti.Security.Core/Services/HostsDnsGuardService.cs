using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Security.Cryptography;
using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

public interface IHostsDnsGuardService : IDisposable
{
    bool IsWatching { get; }
    event EventHandler<HostsTamperAlert>? HostsTampered;

    Task<OperationResult<HostsDnsAuditReport>> AuditAsync(CancellationToken ct = default);
    OperationResult StartWatching();
    OperationResult StopWatching();
    Task<OperationResult> ApplyDnsProtectionAsync(DnsProtectionPreset preset, CancellationToken ct = default);
}

/// <summary>
/// Real Hosts File & DNS Hijack Guard:
/// - Parses %SystemRoot%\System32\drivers\etc\hosts and flags suspicious redirects of security/banking/OS domains
/// - Watches etc\hosts in real time via FileSystemWatcher and computes SHA-256 diff alerts
/// - Reads live DNS servers across active adapters and applies malware-blocking DNS (Cloudflare 1.1.1.2 / Quad9 / DHCP) via netsh
/// </summary>
public sealed class HostsDnsGuardService : IHostsDnsGuardService
{
    private readonly string _hostsPath;
    private FileSystemWatcher? _watcher;
    private string _lastSha256 = string.Empty;
    private readonly object _gate = new();

    private static readonly string[] HighValueDomainKeywords =
    {
        "microsoft", "windowsupdate", "defender", "virustotal", "kaspersky", "bitdefender",
        "avast", "norton", "mcafee", "malwarebytes", "google", "paypal", "binance",
        "coinbase", "bank", "stripe", "github", "apple", "icloud", "live.com", "office.com"
    };

    public HostsDnsGuardService(string? customHostsPath = null)
    {
        _hostsPath = !string.IsNullOrWhiteSpace(customHostsPath)
            ? customHostsPath
            : Path.Combine(Environment.SystemDirectory, "drivers", "etc", "hosts");
    }

    public bool IsWatching => _watcher is not null;

    public event EventHandler<HostsTamperAlert>? HostsTampered;

    public Task<OperationResult<HostsDnsAuditReport>> AuditAsync(CancellationToken ct = default)
    {
        var mappings = new List<HostsMappingEntry>();
        bool exists = File.Exists(_hostsPath);
        string sha256 = string.Empty;

        if (exists)
        {
            try
            {
                sha256 = ComputeSha256(_hostsPath);
                _lastSha256 = sha256;
                var lines = File.ReadAllLines(_hostsPath);
                for (int i = 0; i < lines.Length; i++)
                {
                    var raw = lines[i].Trim();
                    if (string.IsNullOrWhiteSpace(raw) || raw.StartsWith('#'))
                        continue;

                    var hashIdx = raw.IndexOf('#');
                    if (hashIdx >= 0)
                        raw = raw[..hashIdx].Trim();

                    var parts = raw.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length < 2)
                        continue;

                    var ip = parts[0];
                    for (int h = 1; h < parts.Length; h++)
                    {
                        var host = parts[h].ToLowerInvariant();
                        var (isSuspicious, reason) = EvaluateMapping(ip, host);
                        mappings.Add(new HostsMappingEntry
                        {
                            LineNumber = i + 1,
                            IpAddress = ip,
                            Hostname = host,
                            IsSuspicious = isSuspicious,
                            SuspicionReason = reason
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                return Task.FromResult(OperationResult<HostsDnsAuditReport>.Fail($"Failed to read hosts file: {ex.Message}", "HOSTS_READ_ERROR"));
            }
        }

        var adapters = new List<AdapterDnsInfo>();
        try
        {
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.NetworkInterfaceType == NetworkInterfaceType.Loopback ||
                    nic.NetworkInterfaceType == NetworkInterfaceType.Tunnel)
                    continue;
                if (nic.OperationalStatus != OperationalStatus.Up)
                    continue;

                var props = nic.GetIPProperties();
                var dns = props.DnsAddresses.Select(a => a.ToString()).Distinct().ToList();
                adapters.Add(new AdapterDnsInfo
                {
                    InterfaceName = nic.Name,
                    Status = nic.OperationalStatus.ToString(),
                    DnsServers = dns
                });
            }
        }
        catch { }

        var report = new HostsDnsAuditReport
        {
            CheckedAt = DateTimeOffset.UtcNow,
            HostsFilePath = _hostsPath,
            HostsFileExists = exists,
            HostsSha256 = sha256,
            TotalMappings = mappings.Count,
            SuspiciousMappings = mappings.Count(m => m.IsSuspicious),
            Mappings = mappings,
            Adapters = adapters
        };

        return Task.FromResult(OperationResult<HostsDnsAuditReport>.Ok(
            report,
            report.SuspiciousMappings > 0
                ? $"Warning: {report.SuspiciousMappings} suspicious hosts mapping(s) detected out of {report.TotalMappings}."
                : $"Hosts file checked ({report.TotalMappings} mapping(s), 0 suspicious) · {adapters.Count} active adapter(s)."));
    }

    public OperationResult StartWatching()
    {
        lock (_gate)
        {
            if (_watcher is not null)
                return OperationResult.Ok("Hosts file guard is already active.");

            var dir = Path.GetDirectoryName(_hostsPath);
            var file = Path.GetFileName(_hostsPath);
            if (string.IsNullOrWhiteSpace(dir) || !Directory.Exists(dir))
                return OperationResult.Fail($"Hosts directory not found: {dir}", "DIR_NOT_FOUND");

            try
            {
                if (File.Exists(_hostsPath))
                    _lastSha256 = ComputeSha256(_hostsPath);

                var fsw = new FileSystemWatcher(dir, file)
                {
                    NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.Size | NotifyFilters.CreationTime | NotifyFilters.FileName,
                    EnableRaisingEvents = true
                };
                fsw.Changed += OnHostsChanged;
                fsw.Created += OnHostsChanged;
                fsw.Renamed += OnHostsChanged;
                _watcher = fsw;
                return OperationResult.Ok("Hosts & DNS Hijack Guard is now watching system hosts file in real time.");
            }
            catch (Exception ex)
            {
                return OperationResult.Fail($"Could not start Hosts Guard: {ex.Message}", "WATCHER_ERROR");
            }
        }
    }

    public OperationResult StopWatching()
    {
        lock (_gate)
        {
            if (_watcher is not null)
            {
                _watcher.EnableRaisingEvents = false;
                _watcher.Dispose();
                _watcher = null;
            }
            return OperationResult.Ok("Hosts Guard stopped.");
        }
    }

    public async Task<OperationResult> ApplyDnsProtectionAsync(DnsProtectionPreset preset, CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
            return OperationResult.Fail("DNS switching via netsh requires Windows.", "UNSUPPORTED_OS");

        var activeAdapters = NetworkInterface.GetAllNetworkInterfaces()
            .Where(n => n.OperationalStatus == OperationalStatus.Up &&
                        n.NetworkInterfaceType != NetworkInterfaceType.Loopback &&
                        n.NetworkInterfaceType != NetworkInterfaceType.Tunnel)
            .Select(n => n.Name)
            .Distinct()
            .ToList();

        if (activeAdapters.Count == 0)
            return OperationResult.Fail("No active network interface found.", "NO_INTERFACE");

        int updated = 0;
        var errors = new List<string>();

        foreach (var iface in activeAdapters)
        {
            if (preset == DnsProtectionPreset.AutomaticDhcp)
            {
                var r = await RunNetshAsync(new[] { "interface", "ip", "set", "dns", $"name={iface}", "source=dhcp" }, ct).ConfigureAwait(false);
                if (r.Success) updated++;
                else errors.Add($"{iface}: {r.Message}");
            }
            else
            {
                var (primary, secondary) = preset == DnsProtectionPreset.CloudflareMalware
                    ? ("1.1.1.2", "1.0.0.2")
                    : ("9.9.9.9", "149.112.112.112");

                var r1 = await RunNetshAsync(new[] { "interface", "ip", "set", "dns", $"name={iface}", "static", primary, "primary" }, ct).ConfigureAwait(false);
                if (r1.Success)
                {
                    await RunNetshAsync(new[] { "interface", "ip", "add", "dns", $"name={iface}", secondary, "index=2" }, ct).ConfigureAwait(false);
                    updated++;
                }
                else
                {
                    errors.Add($"{iface}: {r1.Message}");
                }
            }
        }

        if (updated > 0)
        {
            var label = preset switch
            {
                DnsProtectionPreset.CloudflareMalware => "Cloudflare Malware-Blocking DNS (1.1.1.2 / 1.0.0.2)",
                DnsProtectionPreset.Quad9Secure => "Quad9 Threat-Blocking DNS (9.9.9.9 / 149.112.112.112)",
                _ => "Automatic DHCP DNS"
            };
            return OperationResult.Ok($"Applied {label} on {updated} active network adapter(s).");
        }

        return OperationResult.Fail(
            $"Could not update DNS settings (Administrator privileges required): {string.Join("; ", errors)}",
            "ELEVATION_REQUIRED");
    }

    private void OnHostsChanged(object sender, FileSystemEventArgs e)
    {
        try
        {
            Thread.Sleep(150);
            if (!File.Exists(_hostsPath)) return;
            var newHash = ComputeSha256(_hostsPath);
            if (string.Equals(newHash, _lastSha256, StringComparison.OrdinalIgnoreCase))
                return;

            var prev = _lastSha256;
            _lastSha256 = newHash;

            HostsTampered?.Invoke(this, new HostsTamperAlert
            {
                Timestamp = DateTimeOffset.UtcNow,
                HostsFilePath = _hostsPath,
                PreviousSha256 = prev,
                NewSha256 = newHash,
                Message = $"System hosts file was modified! New SHA-256: {newHash[..12]}..."
            });
        }
        catch { }
    }

    private static (bool Suspicious, string Reason) EvaluateMapping(string ip, string host)
    {
        bool isLoopback = ip is "127.0.0.1" or "::1" or "0.0.0.0";
        if (host is "localhost" or "localhost.localdomain" or "broadcasthost" or "ip6-localhost")
            return (false, string.Empty);

        bool isHighValue = HighValueDomainKeywords.Any(k => host.Contains(k, StringComparison.OrdinalIgnoreCase));
        if (isHighValue && isLoopback)
            return (true, "Blocks access to a security/OS/financial domain by redirecting it to loopback.");
        if (isHighValue && !isLoopback)
            return (true, $"Redirects high-value domain '{host}' to external IP {ip} (possible phishing/MITM hijack).");
        if (!isLoopback)
            return (true, $"Non-local IP override ({ip}) for '{host}'.");

        return (false, string.Empty);
    }

    private static string ComputeSha256(string path)
    {
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        return Convert.ToHexString(SHA256.HashData(fs));
    }

    private static async Task<OperationResult> RunNetshAsync(string[] args, CancellationToken ct)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "netsh.exe",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };
            foreach (var a in args) psi.ArgumentList.Add(a);

            using var proc = Process.Start(psi);
            if (proc is null)
                return OperationResult.Fail("Failed to launch netsh.exe.");

            var stdout = await proc.StandardOutput.ReadToEndAsync(ct).ConfigureAwait(false);
            var stderr = await proc.StandardError.ReadToEndAsync(ct).ConfigureAwait(false);
            await proc.WaitForExitAsync(ct).ConfigureAwait(false);

            return proc.ExitCode == 0
                ? OperationResult.Ok("OK")
                : OperationResult.Fail((string.IsNullOrWhiteSpace(stderr) ? stdout : stderr).Trim());
        }
        catch (Exception ex)
        {
            return OperationResult.Fail(ex.Message);
        }
    }

    public void Dispose() => StopWatching();
}
