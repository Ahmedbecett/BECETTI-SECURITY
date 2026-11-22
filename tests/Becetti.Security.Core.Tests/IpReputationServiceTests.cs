using System.Text.Json;
using Becetti.Security.Core.Models;
using Becetti.Security.Core.Services;

namespace Becetti.Security.Core.Tests;

/// <summary>
/// Exercises IpReputationService.ParseReport against sample JSON shaped
/// exactly like backend/becetti-ai/api/_abuseipdblib.js's normalizeCheckResult
/// output (see abuseipdb-check.js) — no HTTP call involved.
/// </summary>
public sealed class IpReputationServiceTests
{
    [Fact]
    public void ParseReport_MaliciousIp_MapsAllFields()
    {
        const string json = """
            {
              "status": "completed",
              "ipAddress": "118.25.6.39",
              "isPublic": true,
              "ipVersion": 4,
              "abuseConfidenceScore": 100,
              "totalReports": 1847,
              "numDistinctUsers": 42,
              "lastReportedAtUtc": "2026-11-18T12:00:00+00:00",
              "countryCode": "CN",
              "countryName": "China",
              "usageType": "Data Center/Web Hosting/Transit",
              "isp": "Tencent Cloud Computing (Beijing) Co. Ltd",
              "domain": "tencent.com",
              "isTor": false,
              "isWhitelisted": false,
              "verdict": "malicious"
            }
            """;

        using var doc = JsonDocument.Parse(json);
        var report = IpReputationService.ParseReport(doc.RootElement);

        Assert.Equal("118.25.6.39", report.IpAddress);
        Assert.True(report.IsPublic);
        Assert.Equal(4, report.IpVersion);
        Assert.Equal(100, report.AbuseConfidenceScore);
        Assert.Equal(1847, report.TotalReports);
        Assert.Equal(42, report.NumDistinctUsers);
        Assert.NotNull(report.LastReportedAtUtc);
        Assert.Equal("CN", report.CountryCode);
        Assert.Equal("China", report.CountryName);
        Assert.Equal("Tencent Cloud Computing (Beijing) Co. Ltd", report.Isp);
        Assert.Equal(IpReputationVerdict.Malicious, report.Verdict);
        Assert.Contains("malicious", report.Message);
        Assert.Contains("100%", report.Message);
    }

    [Fact]
    public void ParseReport_CleanIp_NoReports_HasCleanVerdictAndMessage()
    {
        const string json = """
            {
              "status": "completed",
              "ipAddress": "1.1.1.1",
              "isPublic": true,
              "ipVersion": 4,
              "abuseConfidenceScore": 0,
              "totalReports": 0,
              "numDistinctUsers": 0,
              "lastReportedAtUtc": null,
              "countryCode": "AU",
              "countryName": "Australia",
              "usageType": "Content Delivery Network",
              "isp": "Cloudflare, Inc.",
              "domain": "cloudflare.com",
              "isTor": false,
              "isWhitelisted": true,
              "verdict": "clean"
            }
            """;

        using var doc = JsonDocument.Parse(json);
        var report = IpReputationService.ParseReport(doc.RootElement);

        Assert.Equal(IpReputationVerdict.Clean, report.Verdict);
        Assert.Equal(0, report.TotalReports);
        Assert.True(report.IsWhitelisted);
        Assert.Null(report.LastReportedAtUtc);
        Assert.Contains("no abuse reports", report.Message);
    }

    [Fact]
    public void ParseReport_SuspiciousIp_WithOldLowConfidenceReports_MapsVerdict()
    {
        const string json = """
            {
              "status": "completed",
              "ipAddress": "203.0.113.5",
              "abuseConfidenceScore": 40,
              "totalReports": 3,
              "numDistinctUsers": 2,
              "verdict": "suspicious"
            }
            """;

        using var doc = JsonDocument.Parse(json);
        var report = IpReputationService.ParseReport(doc.RootElement);

        Assert.Equal(IpReputationVerdict.Suspicious, report.Verdict);
        Assert.Equal(40, report.AbuseConfidenceScore);
        Assert.Contains("suspicious", report.Message);
    }

    [Fact]
    public void ParseReport_CleanIp_WithOldReports_MentionsReportCountInMessage()
    {
        const string json = """
            {
              "status": "completed",
              "ipAddress": "198.51.100.7",
              "abuseConfidenceScore": 5,
              "totalReports": 2,
              "numDistinctUsers": 1,
              "verdict": "clean"
            }
            """;

        using var doc = JsonDocument.Parse(json);
        var report = IpReputationService.ParseReport(doc.RootElement);

        Assert.Equal(IpReputationVerdict.Clean, report.Verdict);
        Assert.Contains("2 old/low-confidence", report.Message);
    }
}
