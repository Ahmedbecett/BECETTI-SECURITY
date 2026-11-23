using System.Text;
using Becetti.Security.Core.Models;
using Becetti.Security.Core.Services;

namespace Becetti.Security.Core.Tests;

/// <summary>
/// Deterministic unit tests for the 5-Engine Open-Source Multi-AV Orchestrator
/// (ClamAV, YARA-X, CAPA, YARA v4.6.0, Defender) and the Global Domain, Hosting,
/// DNS &amp; IP Security Intelligence Suite (DoH, RDAP, Email SPF/DMARC/DKIM, crt.sh, Export).
/// </summary>
public sealed class MultiEngineAndDomainHostingTests : IDisposable
{
    private readonly string _tempDir;

    public MultiEngineAndDomainHostingTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "becetti-multi-domain-tests-" + Guid.NewGuid().ToString("N"));
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
    //  Multi-Engine Open-Source Antivirus Orchestrator Tests
    // -------------------------------------------------------------------------

    [Fact]
    public void MultiEngineAv_SelectsExactOfficialWindowsX64GitHubAssets()
    {
        var clamJson = """
            {"tag_name":"clamav-1.5.5","assets":[
              {"name":"clamav-1.5.5.tar.gz","browser_download_url":"https://example/src.tar.gz"},
              {"name":"clamav-1.5.5.win.x64.zip","browser_download_url":"https://github.com/Cisco-Talos/clamav/releases/download/clamav-1.5.5/clamav-1.5.5.win.x64.zip"}
            ]}
            """;
        var (tag1, name1, url1) = MultiEngineAvService.SelectOfficialReleaseAssetUrl(clamJson, @"clamav-.*win\.x64\.zip$");
        Assert.Equal("clamav-1.5.5", tag1);
        Assert.Equal("clamav-1.5.5.win.x64.zip", name1);
        Assert.Contains("clamav-1.5.5.win.x64.zip", url1);

        var yxJson = """
            {"tag_name":"v1.24.0","assets":[
              {"name":"yara-x-capi-v1.24.0-x86_64-pc-windows-msvc.zip","browser_download_url":"https://example/capi.zip"},
              {"name":"yara-x-v1.24.0-x86_64-pc-windows-msvc.zip","browser_download_url":"https://github.com/VirusTotal/yara-x/releases/download/v1.24.0/yara-x-v1.24.0-x86_64-pc-windows-msvc.zip"}
            ]}
            """;
        var (tag2, name2, url2) = MultiEngineAvService.SelectOfficialReleaseAssetUrl(yxJson, @"^yara-x-v.*-x86_64-pc-windows-msvc\.zip$");
        Assert.Equal("v1.24.0", tag2);
        Assert.Equal("yara-x-v1.24.0-x86_64-pc-windows-msvc.zip", name2);
        Assert.DoesNotContain("capi", url2);

        var capaJson = """
            {"tag_name":"v10.0.0","assets":[
              {"name":"capa-v10.0.0-windows.zip","browser_download_url":"https://github.com/mandiant/capa/releases/download/v10.0.0/capa-v10.0.0-windows.zip"}
            ]}
            """;
        var (tag3, name3, _) = MultiEngineAvService.SelectOfficialReleaseAssetUrl(capaJson, @"^capa-v.*-windows\.zip$");
        Assert.Equal("v10.0.0", tag3);
        Assert.Equal("capa-v10.0.0-windows.zip", name3);
    }

    [Fact]
    public void MultiEngineAv_ParsesClamAvYaraXAndCapaOutputsAccurately()
    {
        var clamHit = MultiEngineAvService.ParseClamScanOutput(1, @"C:\tmp\eicar.com: Win.Test.EICAR_HDB-1 FOUND", "", 42);
        Assert.True(clamHit.ThreatDetected);
        Assert.Equal("Malicious", clamHit.Verdict);
        Assert.Contains("EICAR", clamHit.DetectionSummary);

        var clamClean = MultiEngineAvService.ParseClamScanOutput(0, "", "", 18);
        Assert.False(clamClean.ThreatDetected);
        Assert.Equal("Clean", clamClean.Verdict);

        var yxHit = MultiEngineAvService.ParseYaraXOutput(0, "Becetti_Ransomware_ShadowCopy_Wipe C:\\tmp\\sample.exe", "", 11);
        Assert.True(yxHit.ThreatDetected);
        Assert.Equal("Malicious", yxHit.Verdict);

        var capaSampleJson = """
            {"rules":{
              "check for time delay via GetTickCount":{"meta":{"namespace":"anti-analysis/anti-debugging","attack":[{"id":"T1497.003"}]}},
              "encrypt data using AES":{"meta":{"namespace":"impact/cryptography","attack":[{"id":"T1486"}]}},
              "capture keystrokes":{"meta":{"namespace":"collection/keylog","attack":[{"id":"T1056.001"}]}}
            }}
            """;
        var (capaVerdict, caps) = MultiEngineAvService.ParseCapaJsonOutput(0, capaSampleJson, "", 320);
        Assert.Equal("Suspicious", capaVerdict.Verdict);
        Assert.Equal(3, caps.Count);
        Assert.Contains(caps, c => c.Contains("T1486"));
    }

    [Fact]
    public async Task MultiEngineAv_ReportsAllFiveOpenSourceAndLocalEngines()
    {
        var settings = new SettingsService(_tempDir);
        var defender = new DefenderService();
        var yara = new YaraEngineService(new HttpClient(), settings);
        var av = new MultiEngineAvService(new HttpClient(), settings, defender, yara);

        var res = await av.GetEnginesStatusAsync();
        Assert.True(res.Success);
        Assert.NotNull(res.Value);
        Assert.Equal(5, res.Value!.Count);
        Assert.Contains(res.Value, e => e.EngineId == "defender");
        Assert.Contains(res.Value, e => e.EngineId == "yara");
        Assert.Contains(res.Value, e => e.EngineId == "clamav" && e.CanAutoInstall && e.SupportsSignatureUpdate);
        Assert.Contains(res.Value, e => e.EngineId == "yarax" && e.CanAutoInstall);
        Assert.Contains(res.Value, e => e.EngineId == "capa" && e.CanAutoInstall);
    }

    // -------------------------------------------------------------------------
    //  Global Domain, Hosting, DNS & IP Security Intelligence Suite Tests
    // -------------------------------------------------------------------------

    [Fact]
    public void DomainHosting_NormalizesUrlsDomainsAndIpsCorrectly()
    {
        var (d1, isIp1, err1) = DomainHostingIntelService.NormalizeTarget("https://Example.COM/login?a=1");
        Assert.Equal("example.com", d1);
        Assert.False(isIp1);
        Assert.Empty(err1);

        var (ip, isIp2, err2) = DomainHostingIntelService.NormalizeTarget("1.1.1.1");
        Assert.Equal("1.1.1.1", ip);
        Assert.True(isIp2);
        Assert.Empty(err2);

        var (_, _, err3) = DomainHostingIntelService.NormalizeTarget("not a valid target!!");
        Assert.NotEmpty(err3);
    }

    [Fact]
    public void DomainHosting_ParsesDohDnsRdapAndCrtShJson()
    {
        var dohJson = """{"Status":0,"AD":true,"Answer":[{"name":"cloudflare.com.","type":1,"TTL":300,"data":"104.16.132.229"}]}""";
        var (recs, ad) = DomainHostingIntelService.ParseDohJson(dohJson, "A");
        Assert.True(ad);
        Assert.Single(recs);
        Assert.Equal("A", recs[0].RecordType);
        Assert.Equal("104.16.132.229", recs[0].Data);

        var rdapJson = """
            {
              "ldhName":"EXAMPLE.COM",
              "status":["client transfer prohibited"],
              "nameservers":[{"ldhName":"a.iana-servers.net"}],
              "events":[
                {"eventAction":"registration","eventDate":"1995-08-14T04:00:00Z"},
                {"eventAction":"expiration","eventDate":"2030-08-13T04:00:00Z"}
              ],
              "entities":[{"roles":["registrar"],"vcardArray":["vcard",[["fn",{},"text","RESERVED-Internet Assigned Numbers Authority"]]]}]
            }
            """;
        var rdap = DomainHostingIntelService.ParseRdapJson(rdapJson, "example.com");
        Assert.True(rdap.Available);
        Assert.Contains("Internet Assigned Numbers Authority", rdap.Registrar);
        Assert.Single(rdap.NameServers);
        Assert.True(rdap.DaysUntilExpiry > 0);

        var crtJson = """[{"name_value":"*.api.example.com\nwww.example.com","issuer_name":"C=US, O=Let's Encrypt, CN=R3","not_after":"2027-01-15T00:00:00"}]""";
        var subs = DomainHostingIntelService.ParseCrtShJson(crtJson, "example.com");
        Assert.Equal(2, subs.Count);
        Assert.Contains(subs, s => s.Subdomain == "api.example.com" && s.IssuerName == "R3");
    }

    [Fact]
    public void DomainHosting_GradesEmailSpfDmarcDkimAccurately()
    {
        var strong = DomainHostingIntelService.EvaluateEmailSecurity(
            "secure.example",
            new[] { "10 aspmx.l.google.com." },
            new[] { "v=spf1 include:_spf.google.com -all" },
            "v=DMARC1; p=reject; rua=mailto:dmarc@secure.example",
            new[] { "google" },
            hasMtaSts: true,
            hasBimi: true);

        Assert.Equal("A+", strong.EmailGrade);
        Assert.Equal(100, strong.EmailSecurityScore);
        Assert.Equal("Google Workspace", strong.MailProviderGuess);

        var weak = DomainHostingIntelService.EvaluateEmailSecurity(
            "weak.example",
            Array.Empty<string>(),
            Array.Empty<string>(),
            null,
            Array.Empty<string>(),
            hasMtaSts: false,
            hasBimi: false);

        Assert.Equal("F", weak.EmailGrade);
        Assert.True(weak.Recommendations.Count >= 3);
    }

    [Fact]
    public async Task DomainHosting_ExportsHtmlAndJsonAuditReports()
    {
        var settings = new SettingsService(_tempDir);
        var svc = new DomainHostingIntelService(new HttpClient(), new ThreatFeedService(new HttpClient(), settings));
        var sample = new CompleteDomainHostingReport
        {
            NormalizedTarget = "example.com",
            OverallScore = 94,
            OverallGrade = "A+",
            Summary = "example.com · Overall Grade A+ (94/100)",
            DnsRecords = new[] { new DnsRecordItem { RecordType = "A", Name = "example.com", Ttl = 300, Data = "93.184.216.34" } }
        };

        var htmlPath = Path.Combine(_tempDir, "domain.html");
        var jsonPath = Path.Combine(_tempDir, "domain.json");
        var hRes = await svc.ExportHtmlReportAsync(sample, htmlPath);
        var jRes = await svc.ExportJsonReportAsync(sample, jsonPath);

        Assert.True(hRes.Success);
        Assert.True(jRes.Success);
        Assert.Contains("93.184.216.34", await File.ReadAllTextAsync(htmlPath, Encoding.UTF8));
        Assert.Contains("example.com", await File.ReadAllTextAsync(jsonPath, Encoding.UTF8));
    }
}
