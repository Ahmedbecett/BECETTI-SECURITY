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
    public void ParseStatusJson_ExplicitUnavailable_ReportsRawError()
    {
        // Mirrors what the real catch-wrapped PowerShell script emits when
        // Get-MpComputerStatus itself throws (e.g. a real device where Defender's
        // WMI provider could not load because its service was stopped/disabled).
        const string json = """{"Available": false, "Error": "Provider load failure"}""";

        var status = DefenderService.ParseStatusJson(json);

        Assert.False(status.Available);
        Assert.Equal("Provider load failure", status.RawError);
    }

    [Fact]
    public void ParseStatusJson_NormalPayloadWithoutAvailableKey_IsStillAvailable()
    {
        // A real successful Get-MpComputerStatus payload never includes an "Available" key;
        // the explicit-false detection above must not misclassify it.
        const string json = """{"AntivirusEnabled": true}""";

        var status = DefenderService.ParseStatusJson(json);

        Assert.True(status.Available);
        Assert.True(status.AntivirusEnabled);
    }

    [Fact]
    public void HumanizeDefenderUnavailable_ProviderLoadFailure_ExplainsDefenderIsDisabled()
    {
        var message = DefenderService.HumanizeDefenderUnavailable("Provider load failure");

        Assert.Contains("Windows Defender", message);
        Assert.Contains("disabled", message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Provider load failure", message);
    }

    [Fact]
    public void HumanizeDefenderUnavailable_UnknownError_PassesThroughUnchanged()
    {
        var message = DefenderService.HumanizeDefenderUnavailable("Some completely different error");

        Assert.Equal("Some completely different error", message);
    }

    [Fact]
    public void HumanizeDefenderUnavailable_Null_ReturnsFallbackText()
    {
        var message = DefenderService.HumanizeDefenderUnavailable(null);

        Assert.False(string.IsNullOrWhiteSpace(message));
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

    // FindMpCmdRun() originally only checked "Program Files\Windows Defender\
    // MpCmdRun.exe", which a real tester's machine did not have - their only
    // copy was under the versioned ProgramData "Platform" folder, so the app
    // wrongly reported Defender as "not found" despite it being installed and
    // working. These tests cover the version-folder parsing/selection logic
    // that fixes that (the OperatingSystem.IsWindows() guard in the public
    // FindMpCmdRun() itself is not exercised here since these tests also run
    // on non-Windows CI).

    [Theory]
    [InlineData("4.18.26080.3", "4.18.26080.3")]
    [InlineData("4.18.26080.3-0", "4.18.26080.3")] // trailing "-<build>" suffix seen on real machines
    [InlineData("not-a-version", "0.0.0.0")] // unparseable folder name must not throw
    public void ParsePlatformVersion_Cases(string folderName, string expectedVersion)
    {
        Assert.Equal(Version.Parse(expectedVersion), DefenderService.ParsePlatformVersion(folderName));
    }

    [Fact]
    public void FindNewestInPlatformFolder_PicksHighestVersionWithMpCmdRunPresent()
    {
        var root = Path.Combine(Path.GetTempPath(), "becetti-defender-platform-test-" + Guid.NewGuid().ToString("N"));
        var older = Path.Combine(root, "4.18.26070.1-0");
        var newer = Path.Combine(root, "4.18.26080.3-0");
        var newestButEmpty = Path.Combine(root, "4.18.26090.1-0"); // no MpCmdRun.exe inside - must be skipped
        try
        {
            Directory.CreateDirectory(older);
            Directory.CreateDirectory(newer);
            Directory.CreateDirectory(newestButEmpty);
            File.WriteAllText(Path.Combine(older, "MpCmdRun.exe"), string.Empty);
            File.WriteAllText(Path.Combine(newer, "MpCmdRun.exe"), string.Empty);

            var result = DefenderService.FindNewestInPlatformFolder(root);

            Assert.Equal(Path.Combine(newer, "MpCmdRun.exe"), result);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void FindNewestInPlatformFolder_MissingDirectory_ReturnsNull()
    {
        var missing = Path.Combine(Path.GetTempPath(), "becetti-defender-platform-missing-" + Guid.NewGuid().ToString("N"));
        Assert.Null(DefenderService.FindNewestInPlatformFolder(missing));
    }

    [Fact]
    public void ParseRansomwareJson_Enabled_WithFolders()
    {
        const string json = """
            {
              "Available": true,
              "EnableControlledFolderAccess": 1,
              "ProtectedFolders": ["C:\\Users\\Test\\Documents", "C:\\Users\\Test\\Pictures"],
              "AllowedApplications": "C:\\Tools\\trusted.exe"
            }
            """;

        var status = DefenderService.ParseRansomwareJson(json);

        Assert.True(status.Available);
        Assert.True(status.ControlledFolderAccessEnabled);
        Assert.Equal("Enabled (Block)", status.ControlledFolderAccessState);
        Assert.Equal(2, status.ProtectedFolders.Count);
        Assert.Single(status.AllowedApplications); // PowerShell emits a bare string for single-element arrays
    }

    [Fact]
    public void ParseRansomwareJson_Disabled()
    {
        const string json = """{"Available": true, "EnableControlledFolderAccess": 0}""";
        var status = DefenderService.ParseRansomwareJson(json);

        Assert.True(status.Available);
        Assert.False(status.ControlledFolderAccessEnabled);
        Assert.Equal("Disabled", status.ControlledFolderAccessState);
        Assert.Empty(status.ProtectedFolders);
    }

    [Fact]
    public void ParseRansomwareJson_Unavailable_ReportsError()
    {
        const string json = """{"Available": false, "Error": "Access denied"}""";
        var status = DefenderService.ParseRansomwareJson(json);

        Assert.False(status.Available);
        Assert.Equal("Access denied", status.RawError);
    }

    [Fact]
    public void ParseRansomwareJson_Empty_ReturnsUnavailable()
    {
        var status = DefenderService.ParseRansomwareJson(string.Empty);
        Assert.False(status.Available);
        Assert.NotNull(status.RawError);
    }
}
