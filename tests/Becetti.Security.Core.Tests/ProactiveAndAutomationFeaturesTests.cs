using System.Text;
using Becetti.Security.Core.Services;
using Xunit;

namespace Becetti.Security.Core.Tests;

public sealed class ProactiveAndAutomationFeaturesTests : IDisposable
{
    private readonly string _tempDir;

    public ProactiveAndAutomationFeaturesTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "becetti-proactive-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        try { if (Directory.Exists(_tempDir)) Directory.Delete(_tempDir, recursive: true); } catch { }
    }

    [Fact]
    public async Task HardeningRemediation_RejectsManualOnlyCheckSafely()
    {
        if (!OperatingSystem.IsWindows())
            return;

        var svc = new WindowsHardeningService();
        var audit = await svc.AuditAsync();
        Assert.True(audit.Success);
        Assert.NotNull(audit.Value);
        Assert.True(audit.Value!.Checks.Count >= 8);

        var manualRes = await svc.RemediateCheckAsync("secureboot", createRestorePoint: false);
        Assert.False(manualRes.Success);
        Assert.Equal("MANUAL_ONLY", manualRes.ErrorCode);
    }

    [Fact]
    public async Task BrowserExtensionAuditor_ScoresHighRiskManifestAndAuditsHost()
    {
        var extDir = Path.Combine(_tempDir, "ext1");
        Directory.CreateDirectory(extDir);
        var manifestPath = Path.Combine(extDir, "manifest.json");
        var json = "{\"name\":\"Suspicious Helper\",\"version\":\"1.2.3\",\"permissions\":[\"cookies\",\"debugger\",\"nativeMessaging\"],\"host_permissions\":[\"<all_urls>\"]}";
        await File.WriteAllTextAsync(manifestPath, json);

        var parsed = BrowserExtensionAuditorService.ParseChromiumManifest("Google Chrome", "Default", "abcdef123456", manifestPath);
        Assert.NotNull(parsed);
        Assert.Equal("Suspicious Helper", parsed!.Name);
        Assert.Equal("Critical", parsed.RiskLevel);
        Assert.Contains("cookies", parsed.RiskyPermissions);
        Assert.Contains("nativeMessaging", parsed.RiskyPermissions);

        var svc = new BrowserExtensionAuditorService();
        var live = await svc.AuditAsync();
        Assert.True(live.Success);
        Assert.NotNull(live.Value);
    }

    [Fact]
    public async Task SoftwareUpdateAuditor_ParsesWingetTableAndBlocksInjectionIds()
    {
        var sample =
            "Name                    Id                      Version    Available  Source\n" +
            "-----------------------------------------------------------------------------\n" +
            "7-Zip 23.01             7zip.7zip               23.01      24.08      winget\n" +
            "Git                     Git.Git                 2.44.0     2.47.1     winget\n" +
            "2 upgrades available.\n";

        var items = SoftwareUpdateAuditorService.ParseWingetUpgradeOutput(sample);
        Assert.Equal(2, items.Count);
        Assert.Equal("7zip.7zip", items[0].PackageId);
        Assert.Equal("24.08", items[0].AvailableVersion);
        Assert.Equal("Git.Git", items[1].PackageId);

        if (OperatingSystem.IsWindows())
        {
            var svc = new SoftwareUpdateAuditorService();
            var bad = await svc.UpgradePackageAsync("7zip.7zip && calc.exe");
            Assert.False(bad.Success);
            Assert.Equal("INVALID_PACKAGE_ID", bad.ErrorCode);
        }
    }

    [Fact]
    public void WifiArpGuard_FlagsOpenWifiAndDetectsDuplicateGatewayMacSpoofing()
    {
        var openWifi =
            "    Name                   : Wi-Fi\n" +
            "    State                  : connected\n" +
            "    SSID                   : FreeAirportWiFi\n" +
            "    BSSID                  : aa:bb:cc:dd:ee:ff\n" +
            "    Authentication         : Open\n" +
            "    Cipher                 : None\n" +
            "    Signal                 : 82%\n";

        var wifiInfo = WifiArpGuardService.ParseWlanInterfacesOutput(openWifi);
        Assert.True(wifiInfo.IsConnected);
        Assert.Equal("Critical", wifiInfo.RiskLevel);

        var arpOutput =
            "Interface: 192.168.1.50 --- 0x6\n" +
            "  Internet Address      Physical Address      Type\n" +
            "  192.168.1.1           aa-bb-cc-11-22-33     dynamic\n" +
            "  192.168.1.99          aa-bb-cc-11-22-33     dynamic\n" +
            "  192.168.1.255         ff-ff-ff-ff-ff-ff     static\n";

        var (entries, gwMac, alerts, spoofed) = WifiArpGuardService.AnalyzeArpTable(arpOutput, "192.168.1.1");
        Assert.Equal("aa-bb-cc-11-22-33", gwMac);
        Assert.True(spoofed);
        Assert.Single(alerts);
        Assert.Equal(2, entries.Count);
        Assert.All(entries, e => Assert.True(e.IsSuspiciousDuplicate));
    }

    [Fact]
    public async Task ProcessDllInspector_InspectsCurrentWindowsProcessModules()
    {
        if (!OperatingSystem.IsWindows())
            return;

        var forensics = new FileForensicsService();
        var svc = new ProcessDllInspectorService(forensics);
        var res = await svc.AuditLoadedModulesAsync(Environment.ProcessId);

        Assert.True(res.Success);
        Assert.NotNull(res.Value);
        Assert.Equal(1, res.Value!.ProcessesScanned);
        Assert.True(res.Value.ModulesInspected > 0);
    }

    [Fact]
    public async Task SecureShredder_OverwritesAndDeletesTempFileAndBlocksSystemDir()
    {
        var target = Path.Combine(_tempDir, "secret.txt");
        var payload = Encoding.UTF8.GetBytes("TOP SECRET BECETTI PAYLOAD 1234567890");
        await File.WriteAllBytesAsync(target, payload);

        var shredder = new SecureShredderService();
        var res = await shredder.ShredFileAsync(target, passes: 3);

        Assert.True(res.Success);
        Assert.NotNull(res.Value);
        Assert.False(File.Exists(target));
        Assert.Equal(3, res.Value!.PassesCompleted);
        Assert.Equal(payload.Length * 3L, res.Value.BytesOverwritten);

        if (OperatingSystem.IsWindows())
        {
            var winNotepad = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "notepad.exe");
            if (File.Exists(winNotepad))
            {
                var blocked = await shredder.ShredFileAsync(winNotepad, passes: 3);
                Assert.False(blocked.Success);
                Assert.Equal("PROTECTED_PATH", blocked.ErrorCode);
            }
        }
    }

    [Fact]
    public async Task PasswordBreachService_ComputesEntropyAndMatchesKAnonymityRange()
    {
        var svc = new PasswordBreachService(new HttpClient());

        var weak = await svc.CheckPasswordAsync("123456", queryHibp: false);
        Assert.True(weak.Success);
        Assert.Equal("Weak", weak.Value!.StrengthRating);

        var strong = await svc.CheckPasswordAsync("Correct!Horse#99Battery$Staple", queryHibp: false);
        Assert.True(strong.Success);
        Assert.Equal("Very Strong", strong.Value!.StrengthRating);
        Assert.Equal(5, strong.Value.Sha1PrefixSent.Length);

        var mockBody = "003D68EB55068C33ACE09247EE4C639306B:42\r\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:3861493\r\n";
        Assert.Equal(3861493L, PasswordBreachService.ParseHibpRangeResponse(mockBody, "1E4C9B93F3F0682250B6CF8331B7EE68FD8"));
        Assert.Equal(0L, PasswordBreachService.ParseHibpRangeResponse(mockBody, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"));
    }

    [Fact]
    public async Task ScanScheduler_ExportsAndImportsPortablePolicyJson()
    {
        var settings = new SettingsService(_tempDir);
        settings.Current.ScheduledScanEnabled = true;
        settings.Current.ScheduledScanIntervalHours = 168;
        settings.Current.HostsGuardEnabled = true;
        settings.Current.FimAutoWatchEnabled = true;
        await settings.SaveAsync();

        var yara = new YaraEngineService(new HttpClient(), settings);
        var hardening = new WindowsHardeningService();
        var events = new EventLogService(_tempDir);
        using var scheduler = new ScanSchedulerService(settings, yara, hardening, events);

        var policyFile = Path.Combine(_tempDir, "policy.json");
        var exp = await scheduler.ExportPolicyAsync(policyFile);
        Assert.True(exp.Success);
        Assert.True(File.Exists(policyFile));

        // Flip settings and verify import restores them cleanly
        settings.Current.ScheduledScanEnabled = false;
        settings.Current.ScheduledScanIntervalHours = 24;
        settings.Current.FimAutoWatchEnabled = false;

        var imp = await scheduler.ImportPolicyAsync(policyFile);
        Assert.True(imp.Success);
        Assert.True(settings.Current.ScheduledScanEnabled);
        Assert.Equal(168, settings.Current.ScheduledScanIntervalHours);
        Assert.True(settings.Current.FimAutoWatchEnabled);
    }

    [Fact]
    public async Task SecurityReportService_GeneratesLocalizedArabicRtlAndEnglishHtmlReports()
    {
        var settings = new SettingsService(_tempDir);
        settings.Current.Language = "ar";
        await settings.SaveAsync();

        var yara = new YaraEngineService(new HttpClient(), settings);
        var hardening = new WindowsHardeningService();
        var quarantine = new QuarantineService(settings);
        var events = new EventLogService(_tempDir);
        await events.RecordAsync("TestEvent", "Verified test event", true);
        using var rtGuard = new RealTimeYaraGuardService(yara, quarantine, settings);
        using var canary = new RansomwareCanaryService();
        using var usb = new UsbAutoScanService(yara);
        using var hosts = new HostsDnsGuardService();
        using var fim = new FileIntegrityMonitorService(settings);

        var reportSvc = new ExecutiveHtmlReportService(settings, hardening, yara, quarantine, events, rtGuard, canary, usb, hosts, fim);
        var outDir = Path.Combine(_tempDir, "reports");

        var arReport = await reportSvc.GenerateExecutiveHtmlReportAsync(outDir);
        Assert.True(arReport.Success);
        Assert.True(File.Exists(arReport.Value!.ReportPath));
        var arHtml = await File.ReadAllTextAsync(arReport.Value.ReportPath);
        Assert.Contains("dir=\"rtl\"", arHtml);
        Assert.Contains("BECETTI SECURITY", arHtml);

        settings.Current.Language = "en";
        var enReport = await reportSvc.GenerateExecutiveHtmlReportAsync(outDir);
        Assert.True(enReport.Success);
        var enHtml = await File.ReadAllTextAsync(enReport.Value!.ReportPath);
        Assert.Contains("dir=\"ltr\"", enHtml);
        Assert.Contains("Executive Security Report", enHtml);
    }

    [Fact]
    public async Task AppLockService_HashesPinWithPbkdf2AndVerifiesSafely()
    {
        var settings = new SettingsService(_tempDir);
        var appLock = new AppLockService(settings);

        var tooShort = await appLock.SetPinAsync("12");
        Assert.False(tooShort.Success);

        var saved = await appLock.SetPinAsync("Becetti@2026");
        Assert.True(saved.Success);
        Assert.True(appLock.IsEnabled);
        Assert.True(appLock.HasPinConfigured);
        Assert.DoesNotContain("Becetti@2026", settings.Current.AppLockPinHash);

        appLock.LockSession();
        Assert.False(appLock.IsSessionUnlocked);
        Assert.False(appLock.VerifyPin("wrong-pin"));
        Assert.False(appLock.IsSessionUnlocked);

        Assert.True(appLock.VerifyPin("Becetti@2026"));
        Assert.True(appLock.IsSessionUnlocked);

        var cleared = await appLock.ClearPinAsync();
        Assert.True(cleared.Success);
        Assert.False(appLock.IsEnabled);
        Assert.False(appLock.HasPinConfigured);
    }
}
