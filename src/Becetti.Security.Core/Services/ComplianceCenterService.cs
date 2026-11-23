using System.Net;
using System.Text;
using System.Text.Json;
using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

public interface IComplianceCenterService
{
    Task<OperationResult<ComplianceAuditReport>> RunComplianceAuditAsync(CancellationToken ct = default);
    Task<OperationResult<string>> ExportComplianceHtmlReportAsync(ComplianceAuditReport report, string outputPath, CancellationToken ct = default);
    Task<OperationResult<string>> ExportComplianceJsonReportAsync(ComplianceAuditReport report, string outputPath, CancellationToken ct = default);
}

/// <summary>
/// #12: Enterprise Compliance Center (CIS Windows 11 Benchmark / NIST CSF / ISO 27001).
/// Aggregates real live findings from Microsoft Defender, Windows Hardening Auditor,
/// Windows Privacy Hardener, and Root Certificate Store Auditor into an auditable compliance
/// scorecard with HTML/Print-to-PDF and JSON export. Zero simulation.
/// </summary>
public sealed class ComplianceCenterService : IComplianceCenterService
{
    private readonly IDefenderService _defender;
    private readonly IWindowsHardeningService _hardening;
    private readonly IWindowsPrivacyHardenerService _privacy;
    private readonly IRootCertAuditorService _rootCerts;
    private readonly IThreatFeedService _feeds;

    public ComplianceCenterService(
        IDefenderService defender,
        IWindowsHardeningService hardening,
        IWindowsPrivacyHardenerService privacy,
        IRootCertAuditorService rootCerts,
        IThreatFeedService feeds)
    {
        _defender = defender;
        _hardening = hardening;
        _privacy = privacy;
        _rootCerts = rootCerts;
        _feeds = feeds;
    }

    public async Task<OperationResult<ComplianceAuditReport>> RunComplianceAuditAsync(CancellationToken ct = default)
    {
        var controls = new List<ComplianceControlResult>();

        // 1. Defender Real-Time Protection (CIS 18.10.43 / NIST DE.CM-4 / ISO A.8.7)
        var defRes = await _defender.GetStatusAsync(ct).ConfigureAwait(false);
        if (defRes.Success && defRes.Value is not null)
        {
            bool rtp = defRes.Value.RealTimeProtectionEnabled;
            controls.Add(new ComplianceControlResult
            {
                ControlId = "CIS-18.10.43 / NIST DE.CM-4",
                Framework = "CIS Win11 + NIST CSF",
                Title = "Endpoint Antivirus Real-Time Protection Active",
                Status = rtp ? "Pass" : "Fail",
                Evidence = rtp ? "Microsoft Defender Real-Time Protection verified ON." : "Real-Time Protection is OFF or unverified.",
                Remediation = "Enable Real-Time Protection in BECETTI SECURITY -> Real-Time Protection."
            });
        }

        // 2. Windows Firewall (CIS 9.1-9.3 / NIST PR.AC-5 / ISO A.8.20)
        var fwRes = await _defender.GetFirewallAsync(ct).ConfigureAwait(false);
        if (fwRes.Success && fwRes.Value is not null && fwRes.Value.Count > 0)
        {
            bool allFw = fwRes.Value.All(p => p.Enabled);
            controls.Add(new ComplianceControlResult
            {
                ControlId = "CIS-9.1-9.3 / ISO A.8.20",
                Framework = "CIS Win11 + ISO 27001",
                Title = "Host-Based Firewall Enabled Across All Profiles",
                Status = allFw ? "Pass" : "Fail",
                Evidence = $"{fwRes.Value.Count(p => p.Enabled)}/{fwRes.Value.Count} Windows Firewall profiles enabled.",
                Remediation = "Enable Domain, Private, and Public profiles via EDR & Hardening -> 1-Click Auto-Fix."
            });
        }

        // 3. Map live Windows Hardening Checks into CIS / NIST controls
        var hardRes = await _hardening.AuditAsync(ct).ConfigureAwait(false);
        if (hardRes.Success && hardRes.Value is not null)
        {
            foreach (var c in hardRes.Value.Checks)
            {
                string mappedStatus = c.Status.Equals("Passed", StringComparison.OrdinalIgnoreCase) ? "Pass"
                    : c.Status.Equals("Failed", StringComparison.OrdinalIgnoreCase) ? "Fail"
                    : "Warning";

                controls.Add(new ComplianceControlResult
                {
                    ControlId = $"CIS-HARD-{c.Id.ToUpperInvariant()}",
                    Framework = "CIS Win11 Benchmark",
                    Title = c.Title,
                    Status = mappedStatus,
                    Evidence = c.CurrentValue,
                    Remediation = c.Recommendation
                });
            }
        }

        // 4. Privacy & Anti-Telemetry Controls (ISO 27701 / GDPR Data Minimization)
        var privRes = await _privacy.AuditPrivacyControlsAsync(ct).ConfigureAwait(false);
        if (privRes.Success && privRes.Value is not null)
        {
            bool ok = privRes.Value.PrivacyScorePercent >= 65;
            controls.Add(new ComplianceControlResult
            {
                ControlId = "ISO-27701 / PRIV-01",
                Framework = "ISO 27701 Privacy",
                Title = "OS Telemetry & Tracking Minimization",
                Status = ok ? "Pass" : "Warning",
                Evidence = $"{privRes.Value.HardenedCount}/{privRes.Value.TotalCount} Windows privacy controls hardened ({privRes.Value.PrivacyScorePercent}%).",
                Remediation = "Open Global Intel -> Privacy & Anti-Telemetry -> Harden All Recommended."
            });
        }

        // 5. Trusted Root CA Integrity (NIST PR.DS-2 / Zero MITM Root CAs)
        var certRes = await _rootCerts.AuditRootCertificatesAsync(ct).ConfigureAwait(false);
        if (certRes.Success && certRes.Value is not null)
        {
            bool clean = certRes.Value.FlaggedCerts == 0;
            controls.Add(new ComplianceControlResult
            {
                ControlId = "NIST PR.DS-2 / TLS-ROOT",
                Framework = "NIST CSF",
                Title = "Trusted Root Certificate Store Integrity",
                Status = clean ? "Pass" : "Warning",
                Evidence = $"{certRes.Value.TotalRootCerts} Root CAs inspected, {certRes.Value.FlaggedCerts} flagged.",
                Remediation = "Inspect flagged CurrentUser Root CAs in SOC Operations -> Root Cert Auditor."
            });
        }

        // 6. Threat Intelligence Feed Freshness (NIST ID.RA-2)
        var feedStatus = _feeds.GetStatus();
        controls.Add(new ComplianceControlResult
        {
            ControlId = "NIST ID.RA-2 / TI-FEED",
            Framework = "NIST CSF",
            Title = "External Threat Intelligence Feeds Synchronized",
            Status = feedStatus.TotalIndicators > 0 ? "Pass" : "Warning",
            Evidence = feedStatus.TotalIndicators > 0
                ? $"{feedStatus.TotalIndicators:N0} abuse.ch IOCs synced."
                : "Global threat feeds not synced yet.",
            Remediation = "Open Global Intel & Radar -> Sync Global Feeds."
        });

        int passed = controls.Count(c => c.Status == "Pass");
        int failed = controls.Count(c => c.Status == "Fail");
        int warn = controls.Count(c => c.Status == "Warning");
        int score = controls.Count == 0 ? 0 : (int)Math.Round(((passed + (warn * 0.5)) / controls.Count) * 100.0);

        var report = new ComplianceAuditReport
        {
            AuditedAt = DateTimeOffset.UtcNow,
            MachineName = Environment.MachineName,
            PassedCount = passed,
            FailedCount = failed,
            WarningCount = warn,
            ComplianceScorePercent = score,
            Controls = controls,
            Summary = $"Compliance Score: {score}% ({passed} Pass, {warn} Warning, {failed} Fail across {controls.Count} CIS/NIST/ISO controls)."
        };

        return OperationResult<ComplianceAuditReport>.Ok(report, report.Summary);
    }

    public async Task<OperationResult<string>> ExportComplianceHtmlReportAsync(ComplianceAuditReport report, string outputPath, CancellationToken ct = default)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(outputPath)!);
            var sb = new StringBuilder();
            sb.AppendLine("<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"/>");
            sb.AppendLine("<title>BECETTI SECURITY — CIS / NIST Compliance Audit Report</title>");
            sb.AppendLine("<style>body{font-family:Segoe UI,sans-serif;background:#0b1120;color:#f1f5f9;padding:32px;max-width:1040px;margin:auto}h1{color:#38bdf8}table{width:100%;border-collapse:collapse;margin-top:20px}th,td{border:1px solid #1e293b;padding:10px;text-align:left;font-size:13px}th{background:#111827}.Pass{color:#10b981;font-weight:700}.Warning{color:#f59e0b;font-weight:700}.Fail{color:#ef4444;font-weight:700}</style></head><body>");
            sb.AppendLine($"<h1>BECETTI SECURITY — Compliance Audit Report</h1>");
            sb.AppendLine($"<p><strong>Host:</strong> {WebUtility.HtmlEncode(report.MachineName)} · <strong>Audited:</strong> {report.AuditedAt.ToLocalTime():f} · <strong>Score:</strong> {report.ComplianceScorePercent}%</p>");
            sb.AppendLine($"<p>{WebUtility.HtmlEncode(report.Summary)}</p>");
            sb.AppendLine("<table><thead><tr><th>Control ID</th><th>Framework</th><th>Control</th><th>Status</th><th>Live Evidence</th><th>Remediation</th></tr></thead><tbody>");
            foreach (var c in report.Controls)
            {
                sb.AppendLine($"<tr><td>{WebUtility.HtmlEncode(c.ControlId)}</td><td>{WebUtility.HtmlEncode(c.Framework)}</td><td>{WebUtility.HtmlEncode(c.Title)}</td><td class=\"{WebUtility.HtmlEncode(c.Status)}\">{WebUtility.HtmlEncode(c.Status)}</td><td>{WebUtility.HtmlEncode(c.Evidence)}</td><td>{WebUtility.HtmlEncode(c.Remediation)}</td></tr>");
            }
            sb.AppendLine("</tbody></table></body></html>");
            await File.WriteAllTextAsync(outputPath, sb.ToString(), Encoding.UTF8, ct).ConfigureAwait(false);
            return OperationResult<string>.Ok(outputPath, $"Exported Compliance HTML Report: {outputPath}");
        }
        catch (Exception ex)
        {
            return OperationResult<string>.Fail($"Failed to export HTML compliance report: {ex.Message}");
        }
    }

    public async Task<OperationResult<string>> ExportComplianceJsonReportAsync(ComplianceAuditReport report, string outputPath, CancellationToken ct = default)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(outputPath)!);
            var json = JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true });
            await File.WriteAllTextAsync(outputPath, json, Encoding.UTF8, ct).ConfigureAwait(false);
            return OperationResult<string>.Ok(outputPath, $"Exported Compliance JSON Report: {outputPath}");
        }
        catch (Exception ex)
        {
            return OperationResult<string>.Fail($"Failed to export JSON compliance report: {ex.Message}");
        }
    }
}
