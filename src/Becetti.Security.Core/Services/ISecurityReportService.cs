using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

/// <summary>
/// Smart Security Reports: assembles one consolidated snapshot from checks
/// that already exist elsewhere (Defender, firewall, device info,
/// Vulnerability Advisor) and renders it as plain text or a simple,
/// dependency-free PDF for sharing/archiving. No data is generated here that
/// the rest of the app hasn't already verified.
/// </summary>
public interface ISecurityReportService
{
    Task<OperationResult<SecurityReportSummary>> BuildReportAsync(CancellationToken ct = default);

    /// <summary>Human-readable plain-text rendering of a report.</summary>
    string RenderText(SecurityReportSummary report);

    /// <summary>Dependency-free single/multi-page PDF rendering of a report.</summary>
    byte[] RenderPdf(SecurityReportSummary report);
}
