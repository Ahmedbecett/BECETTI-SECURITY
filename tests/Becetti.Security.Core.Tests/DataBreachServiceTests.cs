using System.Text.Json;
using Becetti.Security.Core.Models;
using Becetti.Security.Core.Services;

namespace Becetti.Security.Core.Tests;

/// <summary>
/// Exercises DataBreachService's two pure-logic mapping methods:
/// ParseEmailReport (against JSON shaped exactly like
/// backend/becetti-ai/api/_breachlib.js's normalizeEmailBreachAnalytics
/// output) and ParsePasswordRangeResponse (against a real HIBP range-API
/// response shape). No HTTP call involved in either case.
/// </summary>
public sealed class DataBreachServiceTests
{
    [Fact]
    public void ParseEmailReport_Breached_MapsAllFields()
    {
        const string json = """
            {
              "status": "completed",
              "email": "test@example.com",
              "breached": true,
              "breachCount": 1,
              "breaches": [
                {
                  "name": "SweClockers",
                  "domain": "sweclockers.com",
                  "industry": "Electronics",
                  "description": "A 2015 breach exposing usernames, emails and passwords.",
                  "exposedData": ["Usernames", "Email addresses", "Passwords"],
                  "breachDate": "2015",
                  "recordsExposed": 254967,
                  "passwordRisk": "hardtocrack",
                  "verified": true,
                  "referenceUrl": null
                }
              ],
              "riskLabel": "Low",
              "riskScore": 3,
              "message": "Found in 1 known data breach."
            }
            """;

        using var doc = JsonDocument.Parse(json);
        var report = DataBreachService.ParseEmailReport(doc.RootElement);

        Assert.Equal("test@example.com", report.Email);
        Assert.True(report.Breached);
        Assert.Equal(1, report.BreachCount);
        Assert.Single(report.Breaches);
        Assert.Equal("SweClockers", report.Breaches[0].Name);
        Assert.Equal("sweclockers.com", report.Breaches[0].Domain);
        Assert.Equal(3, report.Breaches[0].ExposedData.Count);
        Assert.Equal(254967, report.Breaches[0].RecordsExposed);
        Assert.True(report.Breaches[0].Verified);
        Assert.Equal("Low", report.RiskLabel);
        Assert.Equal(3, report.RiskScore);
        Assert.Contains("1 known data breach", report.Message);
    }

    [Fact]
    public void ParseEmailReport_NotBreached_HasNoBreaches()
    {
        const string json = """
            {
              "status": "completed",
              "email": "clean@example.com",
              "breached": false,
              "breachCount": 0,
              "breaches": [],
              "riskLabel": null,
              "riskScore": null,
              "message": "No known public data breach contains this email address."
            }
            """;

        using var doc = JsonDocument.Parse(json);
        var report = DataBreachService.ParseEmailReport(doc.RootElement);

        Assert.False(report.Breached);
        Assert.Equal(0, report.BreachCount);
        Assert.Empty(report.Breaches);
        Assert.Null(report.RiskLabel);
        Assert.Null(report.RiskScore);
        Assert.Contains("No known public data breach", report.Message);
    }

    [Fact]
    public void ParsePasswordRangeResponse_MatchingSuffix_ReportsBreachedWithCount()
    {
        // SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD
        // prefix = 5BAA6, suffix = 1E4C9B93F3F0682250B6CF8331B7EE68FD
        const string targetSuffix = "1E4C9B93F3F0682250B6CF8331B7EE68FD";
        var suffixesText = "AAAA000000000000000000000000000000:2\r\n" +
                            $"{targetSuffix}:3861493\r\n" +
                            "FFFFFF0000000000000000000000000000:7\r\n";

        var report = DataBreachService.ParsePasswordRangeResponse(suffixesText, targetSuffix);

        Assert.True(report.Breached);
        Assert.Equal(3861493, report.TimesSeen);
        Assert.Contains("known data breaches", report.Message);
    }

    [Fact]
    public void ParsePasswordRangeResponse_NoMatchingSuffix_ReportsNotBreached()
    {
        const string suffixesText = "AAAA000000000000000000000000000000:2\r\nFFFFFF0000000000000000000000000000:7\r\n";

        var report = DataBreachService.ParsePasswordRangeResponse(suffixesText, "0000000000000000000000000000000000");

        Assert.False(report.Breached);
        Assert.Equal(0, report.TimesSeen);
        Assert.Contains("not found", report.Message);
    }

    [Fact]
    public void ParsePasswordRangeResponse_IsCaseInsensitive()
    {
        const string suffixesText = "abcdef0000000000000000000000000000:42\r\n";

        var report = DataBreachService.ParsePasswordRangeResponse(suffixesText, "ABCDEF0000000000000000000000000000");

        Assert.True(report.Breached);
        Assert.Equal(42, report.TimesSeen);
    }
}
