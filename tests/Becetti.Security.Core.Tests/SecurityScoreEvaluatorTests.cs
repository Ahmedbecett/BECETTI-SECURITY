using Becetti.Security.Core.Models;
using Becetti.Security.Core.Services;

namespace Becetti.Security.Core.Tests;

public sealed class SecurityScoreEvaluatorTests
{
    [Fact]
    public void Unavailable_Defender_ReturnsNullScore()
    {
        var result = SecurityScoreEvaluator.Evaluate(null, null, null);
        Assert.Null(result.Score);
        Assert.Equal("Unknown", result.Grade);
    }

    [Fact]
    public void FullyProtected_Device_ScoresHigh()
    {
        var defender = new DefenderStatus
        {
            Available = true,
            AntivirusEnabled = true,
            RealTimeProtectionEnabled = true,
            TamperProtectionEnabled = true,
            RunningMode = "Normal",
            CloudProtectionLevel = "Advanced",
            AntivirusSignatureLastUpdated = DateTimeOffset.Now.AddHours(-2)
        };
        var firewall = new[]
        {
            new FirewallProfileStatus { Name = "Domain", Enabled = true },
            new FirewallProfileStatus { Name = "Private", Enabled = true },
            new FirewallProfileStatus { Name = "Public", Enabled = true }
        };
        var ransomware = new RansomwareProtectionStatus { Available = true, ControlledFolderAccessRaw = 1 };

        var result = SecurityScoreEvaluator.Evaluate(defender, firewall, ransomware);

        Assert.NotNull(result.Score);
        Assert.True(result.Score >= 90, $"Expected a high score, got {result.Score}");
        Assert.Equal("Excellent", result.Grade);
        Assert.Contains(result.Factors, f => f.IsPositive);
        Assert.DoesNotContain(result.Factors, f => !f.IsPositive && f.PointsDelta < 0);
    }

    [Fact]
    public void AntivirusDisabled_NoFirewall_ScoresLow()
    {
        var defender = new DefenderStatus
        {
            Available = true,
            AntivirusEnabled = false,
            RealTimeProtectionEnabled = false,
            TamperProtectionEnabled = false,
            CloudProtectionLevel = "Disabled"
        };
        var firewall = new[] { new FirewallProfileStatus { Name = "Domain", Enabled = false } };

        var result = SecurityScoreEvaluator.Evaluate(defender, firewall, null);

        Assert.NotNull(result.Score);
        Assert.Equal(0, result.Score); // clamped at zero, never negative
        Assert.Equal("At Risk", result.Grade);
        Assert.Contains(result.Factors, f => f.Title == "Antivirus is disabled");
    }

    [Fact]
    public void Score_Is_Never_Outside_0_To_100()
    {
        var defender = new DefenderStatus
        {
            Available = true,
            AntivirusEnabled = true,
            RealTimeProtectionEnabled = true,
            TamperProtectionEnabled = true,
            CloudProtectionLevel = "Advanced",
            AntivirusSignatureLastUpdated = DateTimeOffset.Now
        };
        var firewall = new[] { new FirewallProfileStatus { Name = "Domain", Enabled = true } };
        var ransomware = new RansomwareProtectionStatus { Available = true, ControlledFolderAccessRaw = 1 };

        var result = SecurityScoreEvaluator.Evaluate(defender, firewall, ransomware);

        Assert.InRange(result.Score!.Value, 0, 100);
    }
}
