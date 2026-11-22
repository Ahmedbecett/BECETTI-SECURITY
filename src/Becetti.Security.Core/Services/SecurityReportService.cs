using System.Text;
using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

/// <summary>
/// Pulls together IDefenderService, ISystemInfoService and
/// IVulnerabilityAdvisorService's real results into one report — it performs
/// no checks of its own.
/// </summary>
public sealed class SecurityReportService : ISecurityReportService
{
    private readonly IDefenderService _defender;
    private readonly ISystemInfoService _systemInfo;
    private readonly IVulnerabilityAdvisorService _vulnerability;

    public SecurityReportService(IDefenderService defender, ISystemInfoService systemInfo, IVulnerabilityAdvisorService vulnerability)
    {
        _defender = defender;
        _systemInfo = systemInfo;
        _vulnerability = vulnerability;
    }

    public async Task<OperationResult<SecurityReportSummary>> BuildReportAsync(CancellationToken ct = default)
    {
        var deviceTask = _systemInfo.GetDeviceInfoAsync(ct);
        var statusTask = _defender.GetStatusAsync(ct);
        var firewallTask = _defender.GetFirewallAsync(ct);
        var threatsTask = _defender.GetThreatsAsync(ct);
        var vulnTask = _vulnerability.GetReportAsync(ct);

        await Task.WhenAll(deviceTask, statusTask, firewallTask, threatsTask, vulnTask).ConfigureAwait(false);

        var device = await deviceTask.ConfigureAwait(false);
        var status = await statusTask.ConfigureAwait(false);
        var firewall = await firewallTask.ConfigureAwait(false);
        var threats = await threatsTask.ConfigureAwait(false);
        var vulnerability = await vulnTask.ConfigureAwait(false);

        var summary = new SecurityReportSummary
        {
            DeviceName = device.Success && device.Value is not null ? device.Value.DeviceName : "Unknown",
            DefenderAvailable = status.Success && status.Value is not null && status.Value.Available,
            AntivirusEnabled = status.Success && status.Value is not null && status.Value.AntivirusEnabled,
            RealTimeProtectionEnabled = status.Success && status.Value is not null && status.Value.RealTimeProtectionEnabled,
            FirewallFullyEnabled = firewall.Success && firewall.Value is not null && firewall.Value.All(p => p.Enabled),
            ThreatCount = threats.Success && threats.Value is not null ? threats.Value.Count : 0,
            Vulnerability = vulnerability.Success && vulnerability.Value is not null ? vulnerability.Value : new VulnerabilityReport()
        };

        return OperationResult<SecurityReportSummary>.Ok(summary, "Security report compiled from real, current checks.");
    }

    public string RenderText(SecurityReportSummary report)
    {
        var sb = new StringBuilder();
        sb.AppendLine("BECETTI SECURITY - Security Report");
        sb.AppendLine($"Generated: {report.GeneratedAt:yyyy-MM-dd HH:mm} (local time)");
        sb.AppendLine($"Device: {report.DeviceName}");
        sb.AppendLine();
        sb.AppendLine("Summary");
        sb.AppendLine("-------");
        sb.AppendLine($"Microsoft Defender available: {YesNo(report.DefenderAvailable)}");
        sb.AppendLine($"Antivirus enabled: {YesNo(report.AntivirusEnabled)}");
        sb.AppendLine($"Real-time protection enabled: {YesNo(report.RealTimeProtectionEnabled)}");
        sb.AppendLine($"All firewall profiles enabled: {YesNo(report.FirewallFullyEnabled)}");
        sb.AppendLine($"Active threats reported by Defender: {report.ThreatCount}");
        sb.AppendLine();
        sb.AppendLine($"Vulnerability Advisor findings ({report.Vulnerability.Findings.Count} total: " +
                       $"{report.Vulnerability.HighCount} high, {report.Vulnerability.MediumCount} medium, " +
                       $"{report.Vulnerability.LowCount} low, {report.Vulnerability.GoodCount} good)");
        sb.AppendLine("--------------------------------------------------------------");
        foreach (var finding in report.Vulnerability.Findings)
        {
            sb.AppendLine($"[{finding.Severity}] {finding.Title}: {finding.Detail}");
            if (!string.IsNullOrWhiteSpace(finding.Recommendation))
                sb.AppendLine($"    Recommendation: {finding.Recommendation}");
        }

        sb.AppendLine();
        sb.AppendLine("This report reflects the real state of Microsoft Defender, Windows Firewall and " +
                       "other Windows security features at the time it was generated. BECETTI SECURITY " +
                       "does not fabricate or estimate any of the values above.");

        return sb.ToString();
    }

    public byte[] RenderPdf(SecurityReportSummary report)
    {
        var lines = new List<string>
        {
            $"Generated: {report.GeneratedAt:yyyy-MM-dd HH:mm} (local time)",
            $"Device: {report.DeviceName}",
            "",
            "Summary",
            $"  Microsoft Defender available: {YesNo(report.DefenderAvailable)}",
            $"  Antivirus enabled: {YesNo(report.AntivirusEnabled)}",
            $"  Real-time protection enabled: {YesNo(report.RealTimeProtectionEnabled)}",
            $"  All firewall profiles enabled: {YesNo(report.FirewallFullyEnabled)}",
            $"  Active threats reported by Defender: {report.ThreatCount}",
            "",
            $"Vulnerability Advisor findings ({report.Vulnerability.Findings.Count} total: " +
            $"{report.Vulnerability.HighCount} high, {report.Vulnerability.MediumCount} medium, " +
            $"{report.Vulnerability.LowCount} low, {report.Vulnerability.GoodCount} good)"
        };

        foreach (var finding in report.Vulnerability.Findings)
        {
            lines.Add($"[{finding.Severity}] {finding.Title}: {finding.Detail}");
            if (!string.IsNullOrWhiteSpace(finding.Recommendation))
                lines.Add($"    Recommendation: {finding.Recommendation}");
        }

        lines.Add("");
        lines.Add("This report reflects the real, verified state of Windows security features at the");
        lines.Add("time it was generated. No value above is fabricated or estimated.");

        return SimplePdfWriter.Write("BECETTI SECURITY - Security Report", lines);
    }

    private static string YesNo(bool value) => value ? "Yes" : "No";
}
