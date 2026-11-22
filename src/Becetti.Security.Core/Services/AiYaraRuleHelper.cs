using System.Text;
using System.Text.RegularExpressions;
using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

/// <summary>
/// Helpers powering BECETTI AI Threat Investigator (Feature 10) and AI YARA Rule Studio (Feature 11).
/// Never fabricates results — builds structured prompts from real forensic/YARA outputs and
/// extracts raw .yar rule blocks for genuine live validation with yarac64.exe.
/// </summary>
public static class AiYaraRuleHelper
{
    private static readonly Regex CodeFenceRegex = new(
        @"```(?:yara|yar)?\s*\r?\n([\s\S]*?)```",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    /// <summary>Builds a factual forensic triage prompt combining real YARA matches and static PE/Authenticode forensics.</summary>
    public static string BuildThreatInvestigatorPrompt(
        YaraRuleMatch? match,
        FileForensicsReport? forensics,
        string userLanguageShortCode = "en")
    {
        var sb = new StringBuilder();
        sb.AppendLine("Act as BECETTI AI Threat Investigator. Analyze these REAL local forensic findings and produce:");
        sb.AppendLine("1) Clear verdict (Likely Malicious / Suspicious / Possible False Positive) with reasons based ONLY on the facts below.");
        sb.AppendLine("2) Step-by-step safe remediation playbook inside BECETTI SECURITY (Quarantine, Process termination, Firewall block, or Safe Restore).");
        sb.AppendLine($"Reply concisely in language code '{userLanguageShortCode}'.");
        sb.AppendLine();

        if (match is not null)
        {
            sb.AppendLine("=== YARA ENGINE DETECTION ===");
            sb.AppendLine($"Rule: {match.RuleName}");
            sb.AppendLine($"Severity: {match.Severity} | Category: {match.Category}");
            if (!string.IsNullOrWhiteSpace(match.Description))
                sb.AppendLine($"Description: {match.Description}");
            if (match.Tags.Count > 0)
                sb.AppendLine($"Tags: {string.Join(", ", match.Tags)}");
            sb.AppendLine($"File: {match.FilePath}");
            if (match.MatchedStrings.Count > 0)
            {
                sb.AppendLine("Matched indicators:");
                foreach (var s in match.MatchedStrings.Take(6))
                    sb.AppendLine($"  - {s.DisplayLine}");
            }
            sb.AppendLine();
        }

        if (forensics is not null)
        {
            sb.AppendLine("=== STATIC FILE FORENSICS ===");
            sb.AppendLine($"File: {forensics.FileName} ({forensics.FileSizeBytes:N0} bytes)");
            sb.AppendLine($"SHA-256: {forensics.Sha256}");
            sb.AppendLine($"Shannon Entropy: {forensics.FileEntropy:F2} / 8.00 (Likely Packed/Encrypted: {forensics.IsLikelyPackedOrEncrypted})");
            sb.AppendLine($"PE Binary: {forensics.IsPeBinary} ({forensics.PeArchitecture})");
            sb.AppendLine($"Authenticode Signature: Signed={forensics.Signature.IsSigned}, Trusted={forensics.Signature.IsTrusted}, Status={forensics.Signature.Status}");
            if (!string.IsNullOrWhiteSpace(forensics.Signature.Subject))
                sb.AppendLine($"Signer: {forensics.Signature.Subject}");
            if (forensics.PackerIndicators.Count > 0)
                sb.AppendLine($"Packer sections: {string.Join(", ", forensics.PackerIndicators)}");
            if (forensics.SuspiciousApis.Count > 0)
                sb.AppendLine($"Sensitive APIs: {string.Join(", ", forensics.SuspiciousApis)}");
            sb.AppendLine($"Local static risk: {forensics.RiskAssessment}");
            foreach (var r in forensics.RiskReasons)
                sb.AppendLine($"  - {r}");
        }

        return sb.ToString().Trim();
    }

    /// <summary>Builds a focused prompt asking BECETTI AI to generate a clean, standard YARA 4.x rule with zero external module dependencies.</summary>
    public static string BuildYaraRuleGenerationPrompt(string threatDescriptionOrIocs)
    {
        return "Generate a single valid, ready-to-compile YARA 4.x rule (.yar) for the following threat description or IOCs.\n" +
               "Requirements:\n" +
               "- Use ONLY standard YARA 4.x syntax with NO external modules (do NOT use import \"pe\", \"hash\", or \"cuckoo\").\n" +
               "- Include meta fields: description, author = \"BECETTI AI Rule Studio\", severity, category.\n" +
               "- Use clear ascii/wide/nocase or hex strings and a safe filesize condition.\n" +
               "- Return the YARA rule inside a single ```yara ... ``` code block.\n\n" +
               "Threat / IOCs:\n" + threatDescriptionOrIocs.Trim();
    }

    /// <summary>Extracts the raw .yar source code from an AI markdown response (or raw rule text).</summary>
    public static string? ExtractYaraRuleText(string aiReply)
    {
        if (string.IsNullOrWhiteSpace(aiReply))
            return null;

        var fenceMatch = CodeFenceRegex.Match(aiReply);
        if (fenceMatch.Success)
        {
            var inner = fenceMatch.Groups[1].Value.Trim();
            if (inner.Contains("rule ", StringComparison.Ordinal))
                return inner;
        }

        var ruleIdx = aiReply.IndexOf("rule ", StringComparison.Ordinal);
        if (ruleIdx >= 0)
        {
            var tail = aiReply[ruleIdx..].Trim();
            var lastBrace = tail.LastIndexOf('}');
            if (lastBrace > 0)
                return tail[..(lastBrace + 1)].Trim();
        }

        return null;
    }
}
