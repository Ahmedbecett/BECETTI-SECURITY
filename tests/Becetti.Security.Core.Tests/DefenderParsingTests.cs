using Becetti.Security.Core.Services;

namespace Becetti.Security.Core.Tests;

public sealed class DefenderParsingTests
{
    [Fact]
    public void ParseStatusJson_MapsFields()
    {
        const string json = """
            {
              "AntivirusEnabled": true,
              "RealTimeProtectionEnabled": true,
              "BehaviorMonitorEnabled": true,
              "IoavProtectionEnabled": false,
              "NISEnabled": true,
              "IsTamperProtected": true,
              "AntivirusSignatureVersion": "1.419.123.0",
              "AntivirusSignatureLastUpdated": "2026-11-20T10:00:00.0000000+00:00",
              "QuickScanEndTime": "2026-11-19T08:30:00.0000000+00:00",
              "FullScanEndTime": null,
              "AMRunningMode": "Normal"
            }
            """;

        var status = DefenderService.ParseStatusJson(json);

        Assert.True(status.Available);
        Assert.True(status.AntivirusEnabled);
        Assert.True(status.RealTimeProtectionEnabled);
        Assert.False(status.IoavProtectionEnabled);
        Assert.True(status.NetworkProtectionEnabled);
        Assert.True(status.TamperProtectionEnabled);
        Assert.Equal("1.419.123.0", status.AntivirusSignatureVersion);
        Assert.NotNull(status.AntivirusSignatureLastUpdated);
        Assert.NotNull(status.QuickScanEndTime);
        Assert.Null(status.FullScanEndTime);
        Assert.Equal("Normal", status.RunningMode);
        Assert.False(status.ManagedByAnotherAntivirus);
    }

    [Fact]
    public void ParseStatusJson_PassiveMode_IsManagedByAnotherAntivirus()
    {
        const string json = """
            {
              "AntivirusEnabled": true,
              "RealTimeProtectionEnabled": false,
              "AntivirusSignatureVersion": "1.419.123.0",
              "AMRunningMode": "Passive Mode"
            }
            """;

        var status = DefenderService.ParseStatusJson(json);

        Assert.Equal("Passive Mode", status.RunningMode);
        Assert.True(status.ManagedByAnotherAntivirus);
    }

    [Fact]
    public void DefenderStatus_NoRunningMode_IsNotManagedByAnotherAntivirus()
    {
        var status = new Becetti.Security.Core.Models.DefenderStatus { Available = true, RunningMode = null };
        Assert.False(status.ManagedByAnotherAntivirus);
    }

    [Fact]
    public void ParseStatusJson_MapsCloudProtectionAndSampleSubmission()
    {
        const string json = """
            {
              "AntivirusEnabled": true,
              "MAPSReporting": 2,
              "SubmitSamplesConsent": 1
            }
            """;

        var status = DefenderService.ParseStatusJson(json);

        Assert.Equal("Advanced", status.CloudProtectionLevel);
        Assert.Equal("Send Safe Samples", status.SampleSubmissionMode);
    }

    [Fact]
    public void ParseStatusJson_MissingPreferenceFields_ReportsUnknown()
    {
        const string json = """{"AntivirusEnabled": true}""";

        var status = DefenderService.ParseStatusJson(json);

        Assert.Equal("Unknown", status.CloudProtectionLevel);
        Assert.Equal("Unknown", status.SampleSubmissionMode);
    }

    [Theory]
    [InlineData(0, "Disabled")]
    [InlineData(1, "Basic")]
    [InlineData(2, "Advanced")]
    [InlineData(99, "Unknown")]
    [InlineData(null, "Unknown")]
    public void CloudProtectionLabel_Cases(int? value, string expected)
    {
        Assert.Equal(expected, DefenderService.CloudProtectionLabel(value));
    }

    [Theory]
    [InlineData(0, "Always Prompt")]
    [InlineData(1, "Send Safe Samples")]
    [InlineData(2, "Never Send")]
    [InlineData(3, "Send All Samples")]
    [InlineData(99, "Unknown")]
    [InlineData(null, "Unknown")]
    public void SampleSubmissionLabel_Cases(int? value, string expected)
    {
        Assert.Equal(expected, DefenderService.SampleSubmissionLabel(value));
    }

    [Fact]
    public void ParseStatusJson_Empty_ReturnsUnavailable()
    {
        var status = DefenderService.ParseStatusJson(string.Empty);
        Assert.False(status.Available);
        Assert.NotNull(status.RawError);
    }

    [Fact]
    public void ParseThreatsJson_Array()
    {
        const string json = """
            [
              {
                "ThreatID": "threat-1",
                "ThreatName": "Trojan:Win32/Test",
                "SeverityID": 3,
                "CategoryID": 3,
                "Resources": "file://C:/test.exe",
                "InitialDetectionTime": "2026-11-20T09:00:00.0000000+00:00",
                "ActionSuccess": true,
                "Action": "Quarantine"
              }
            ]
            """;

        var threats = DefenderService.ParseThreatsJson(json);

        Assert.Single(threats);
        Assert.Equal("threat-1", threats[0].ThreatId);
        Assert.Equal("High", threats[0].Severity);
        Assert.Equal("Trojan", threats[0].Category);
        Assert.True(threats[0].ActionSucceeded);
    }

    [Fact]
    public void ParseThreatsJson_SingleObject()
    {
        const string json = """{"ThreatID":"t2","ThreatName":"Virus:X","SeverityID":5,"CategoryID":1,"Resources":"","ActionSuccess":false}""";
        var threats = DefenderService.ParseThreatsJson(json);
        Assert.Single(threats);
        Assert.Equal("Critical", threats[0].Severity);
        Assert.Equal("Virus", threats[0].Category);
    }

    [Fact]
    public void ParseThreatsJson_Empty_ReturnsEmpty()
    {
        Assert.Empty(DefenderService.ParseThreatsJson(string.Empty));
        Assert.Empty(DefenderService.ParseThreatsJson("[]"));
    }

    [Theory]
    [InlineData(1, "Low")]
    [InlineData(2, "Medium")]
    [InlineData(3, "High")]
    [InlineData(4, "Severe")]
    [InlineData(5, "Critical")]
    [InlineData(99, "Unknown")]
    public void SeverityLabel_Cases(int id, string expected)
    {
        Assert.Equal(expected, DefenderService.SeverityLabel(id));
    }
}
