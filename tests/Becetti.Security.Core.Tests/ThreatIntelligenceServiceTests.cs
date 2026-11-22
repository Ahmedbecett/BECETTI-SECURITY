using System.Text.Json;
using Becetti.Security.Core.Models;
using Becetti.Security.Core.Services;

namespace Becetti.Security.Core.Tests;

/// <summary>
/// Exercises ThreatIntelligenceService.ParseReport against sample JSON shaped
/// exactly like backend/becetti-ai/api/_vtlib.js's normalizeAttributes output
/// (see vt-file.js / vt-url.js / vt-analysis.js) — no HTTP call involved.
/// </summary>
public sealed class ThreatIntelligenceServiceTests
{
    [Fact]
    public void ParseReport_ExistingMaliciousFileReport_MapsAllFields()
    {
        const string json = """
            {
              "status": "completed",
              "source": "existing_report",
              "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
              "fileName": "sample.exe",
              "kind": "file",
              "stats": { "malicious": 3, "suspicious": 1, "harmless": 60, "undetected": 8, "timeout": 0, "total": 72 },
              "detectionRatio": "4/72",
              "verdict": "malicious",
              "engines": [
                { "name": "EngineA", "category": "malicious", "result": "Trojan.GenericKD" },
                { "name": "EngineB", "category": "suspicious", "result": "Suspicious.Generic" }
              ],
              "url": null,
              "scanDateUtc": "2026-11-18T12:00:00.000Z",
              "permalink": "https://www.virustotal.com/gui/file/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            }
            """;

        using var doc = JsonDocument.Parse(json);
        var report = ThreatIntelligenceService.ParseReport(doc.RootElement, ThreatIntelTargetType.File);

        Assert.Equal(ThreatIntelStatus.Completed, report.Status);
        Assert.Equal(ThreatIntelTargetType.File, report.TargetType);
        Assert.Equal(ThreatIntelVerdict.Malicious, report.Verdict);
        Assert.Equal("4/72", report.DetectionRatio);
        Assert.Equal(3, report.Malicious);
        Assert.Equal(1, report.Suspicious);
        Assert.Equal(72, report.TotalEngines);
        Assert.Equal(2, report.FlaggedEngines.Count);
        Assert.Equal("EngineA", report.FlaggedEngines[0].EngineName);
        Assert.Equal("Trojan.GenericKD", report.FlaggedEngines[0].Result);
        Assert.NotNull(report.ScanDateUtc);
        Assert.Contains("virustotal.com/gui/file", report.Permalink);
        Assert.Contains("4/72", report.Message);
    }

    [Fact]
    public void ParseReport_NotFound_MapsStatusAndMessage()
    {
        const string json = """
            { "status": "not_found", "sha256": "abc123", "fileName": "unknown.bin", "message": "VirusTotal has no existing report for this file. Re-submit with the file content to request a fresh scan." }
            """;

        using var doc = JsonDocument.Parse(json);
        var report = ThreatIntelligenceService.ParseReport(doc.RootElement, ThreatIntelTargetType.File);

        Assert.Equal(ThreatIntelStatus.NotFound, report.Status);
        Assert.Equal("abc123", report.Sha256);
        Assert.Contains("no existing report", report.Message);
        Assert.Empty(report.FlaggedEngines);
    }

    [Fact]
    public void ParseReport_QueuedUpload_CarriesAnalysisId()
    {
        const string json = """
            { "status": "queued", "id": "analysis-123", "sha256": "abc123", "fileName": "sample.exe", "message": "File submitted to VirusTotal for a fresh scan. Poll /api/vt-analysis with this id for the result." }
            """;

        using var doc = JsonDocument.Parse(json);
        var report = ThreatIntelligenceService.ParseReport(doc.RootElement, ThreatIntelTargetType.File);

        Assert.Equal(ThreatIntelStatus.Queued, report.Status);
        Assert.Equal("analysis-123", report.AnalysisId);
    }

    [Fact]
    public void ParseReport_CompletedCleanUrl_HasNoFlaggedEngines()
    {
        const string json = """
            {
              "status": "completed",
              "id": "u-xyz",
              "kind": "url",
              "stats": { "malicious": 0, "suspicious": 0, "harmless": 68, "undetected": 4, "timeout": 0, "total": 72 },
              "detectionRatio": "0/72",
              "verdict": "clean",
              "engines": [],
              "url": "https://example.com/",
              "scanDateUtc": "2026-11-19T09:00:00.000Z",
              "permalink": "https://www.virustotal.com/gui/url/abcd"
            }
            """;

        using var doc = JsonDocument.Parse(json);
        var report = ThreatIntelligenceService.ParseReport(doc.RootElement, ThreatIntelTargetType.Url);

        Assert.Equal(ThreatIntelStatus.Completed, report.Status);
        Assert.Equal(ThreatIntelTargetType.Url, report.TargetType);
        Assert.Equal(ThreatIntelVerdict.Clean, report.Verdict);
        Assert.Empty(report.FlaggedEngines);
        Assert.Equal("https://example.com/", report.Url);
    }

    [Fact]
    public void ParseReport_StillScanning_ReportsQueuedWithoutStats()
    {
        const string json = """{ "status": "queued", "id": "u-xyz", "message": "VirusTotal is still scanning. Poll again shortly." }""";

        using var doc = JsonDocument.Parse(json);
        var report = ThreatIntelligenceService.ParseReport(doc.RootElement, ThreatIntelTargetType.Url);

        Assert.Equal(ThreatIntelStatus.Queued, report.Status);
        Assert.Equal(0, report.TotalEngines);
        Assert.Equal("VirusTotal is still scanning. Poll again shortly.", report.Message);
    }
}
