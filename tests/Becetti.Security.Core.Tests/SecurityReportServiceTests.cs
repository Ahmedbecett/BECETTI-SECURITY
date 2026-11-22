using Becetti.Security.Core.Models;
using Becetti.Security.Core.Services;

namespace Becetti.Security.Core.Tests;

public sealed class SecurityReportServiceTests
{
    // RenderText/RenderPdf are pure formatting over an already-built SecurityReportSummary
    // and never touch the injected services, so a service instance with no real
    // dependencies is sufficient to exercise them here.
    private static readonly SecurityReportService Service = new(null!, null!, null!);

    private static SecurityReportSummary SampleReport() => new()
    {
        DeviceName = "TEST-PC",
        DefenderAvailable = true,
        AntivirusEnabled = true,
        RealTimeProtectionEnabled = false,
        FirewallFullyEnabled = true,
        ThreatCount = 0,
        Vulnerability = new VulnerabilityReport
        {
            Findings = new[]
            {
                new SecurityFinding { Title = "Real-time protection", Severity = FindingSeverity.High, Detail = "Off.", Recommendation = "Turn it on.", Source = "Get-MpComputerStatus" },
                new SecurityFinding { Title = "Firewall", Severity = FindingSeverity.Good, Detail = "All profiles enabled.", Source = "Get-NetFirewallProfile" }
            }
        }
    };

    [Fact]
    public void RenderText_IncludesDeviceNameAndEveryFinding()
    {
        var text = Service.RenderText(SampleReport());

        Assert.Contains("TEST-PC", text);
        Assert.Contains("Real-time protection", text);
        Assert.Contains("Turn it on.", text);
        Assert.Contains("Firewall", text);
    }

    [Fact]
    public void RenderPdf_ProducesNonEmptyValidPdfBytes()
    {
        var bytes = Service.RenderPdf(SampleReport());

        Assert.NotEmpty(bytes);
        var header = System.Text.Encoding.ASCII.GetString(bytes, 0, 8);
        Assert.Equal("%PDF-1.4", header);
    }
}
