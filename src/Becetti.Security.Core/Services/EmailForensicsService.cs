using System.Text.RegularExpressions;
using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

public interface IEmailForensicsService
{
    Task<OperationResult<EmailForensicsReport>> AnalyzeEmlFileAsync(string emlFilePath, CancellationToken ct = default);
    EmailForensicsReport AnalyzeRawEml(string rawContent, string fileName = "message.eml");
}

/// <summary>
/// #7: EML Email Phishing &amp; Header Forensics Analyzer.
/// Parses RFC 5322 email headers (From, Reply-To, Return-Path, Received hops, SPF/DKIM/DMARC
/// Authentication-Results), detects sender spoofing, extracts embedded URLs, and checks every
/// domain against live abuse.ch URLhaus Threat Feeds. Zero simulation.
/// </summary>
public sealed class EmailForensicsService : IEmailForensicsService
{
    private static readonly Regex UrlRegex = new("https?://[^\\s\"'<>\\)\\]]+", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex EmailAddrRegex = new("[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\\.[A-Za-z]{2,})", RegexOptions.Compiled);
    private static readonly Regex SpfRegex = new("spf=(pass|fail|softfail|neutral|none|permerror|temperror)", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex DkimRegex = new("dkim=(pass|fail|neutral|none|permerror|temperror)", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex DmarcRegex = new("dmarc=(pass|fail|bestguesspass|none)", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private readonly IThreatFeedService _feeds;

    public EmailForensicsService(IThreatFeedService feeds)
    {
        _feeds = feeds;
    }

    public async Task<OperationResult<EmailForensicsReport>> AnalyzeEmlFileAsync(string emlFilePath, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(emlFilePath) || !File.Exists(emlFilePath))
            return OperationResult<EmailForensicsReport>.Fail("Select a valid .eml file to inspect.");

        var raw = await File.ReadAllTextAsync(emlFilePath, ct).ConfigureAwait(false);
        var report = AnalyzeRawEml(raw, Path.GetFileName(emlFilePath));
        return OperationResult<EmailForensicsReport>.Ok(report, report.Summary);
    }

    public EmailForensicsReport AnalyzeRawEml(string rawContent, string fileName = "message.eml")
    {
        var text = rawContent ?? string.Empty;
        int splitIdx = text.IndexOf("\r\n\r\n", StringComparison.Ordinal);
        if (splitIdx < 0) splitIdx = text.IndexOf("\n\n", StringComparison.Ordinal);

        string headerSection = splitIdx >= 0 ? text[..splitIdx] : text;
        string bodySection = splitIdx >= 0 ? text[splitIdx..] : string.Empty;

        // Unfold RFC 5322 folded headers
        var unfolded = Regex.Replace(headerSection, "\\r?\\n[ \\t]+", " ");
        var lines = unfolded.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);

        string from = string.Empty, replyTo = string.Empty, returnPath = string.Empty, subject = string.Empty;
        var authResults = new List<string>();
        var receivedHops = new List<string>();

        foreach (var line in lines)
        {
            int colon = line.IndexOf(':');
            if (colon <= 0) continue;
            var key = line[..colon].Trim();
            var val = line[(colon + 1)..].Trim();

            if (key.Equals("From", StringComparison.OrdinalIgnoreCase)) from = val;
            else if (key.Equals("Reply-To", StringComparison.OrdinalIgnoreCase)) replyTo = val;
            else if (key.Equals("Return-Path", StringComparison.OrdinalIgnoreCase)) returnPath = val;
            else if (key.Equals("Subject", StringComparison.OrdinalIgnoreCase)) subject = val;
            else if (key.Equals("Authentication-Results", StringComparison.OrdinalIgnoreCase)) authResults.Add(val);
            else if (key.Equals("Received", StringComparison.OrdinalIgnoreCase)) receivedHops.Add(val);
        }

        var combinedAuth = string.Join(" ; ", authResults);
        string spf = MatchOrDefault(SpfRegex, combinedAuth, "Not Present");
        string dkim = MatchOrDefault(DkimRegex, combinedAuth, "Not Present");
        string dmarc = MatchOrDefault(DmarcRegex, combinedAuth, "Not Present");

        int risk = 0;
        var findings = new List<string>();

        if (spf is "fail" or "softfail") { risk += 25; findings.Add($"SPF authentication failed ({spf}) — sender IP not authorized."); }
        if (dkim == "fail") { risk += 25; findings.Add("DKIM cryptographic signature verification failed."); }
        if (dmarc == "fail") { risk += 30; findings.Add("DMARC alignment policy failed — high spoofing probability."); }

        var fromDomain = ExtractEmailDomain(from);
        var replyDomain = ExtractEmailDomain(replyTo);
        var returnDomain = ExtractEmailDomain(returnPath);

        if (!string.IsNullOrEmpty(fromDomain) && !string.IsNullOrEmpty(replyDomain) &&
            !fromDomain.Equals(replyDomain, StringComparison.OrdinalIgnoreCase))
        {
            risk += 25;
            findings.Add($"Reply-To domain mismatch ({replyDomain}) vs From domain ({fromDomain}) — classic phishing tactic.");
        }

        if (!string.IsNullOrEmpty(fromDomain) && !string.IsNullOrEmpty(returnDomain) &&
            !fromDomain.Equals(returnDomain, StringComparison.OrdinalIgnoreCase))
        {
            risk += 15;
            findings.Add($"Return-Path domain ({returnDomain}) differs from visible From domain ({fromDomain}).");
        }

        var urls = UrlRegex.Matches(bodySection)
            .Select(m => m.Value.TrimEnd('.', ',', ';'))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(50)
            .ToList();

        var feedHits = new List<string>();
        foreach (var u in urls)
        {
            var hit = _feeds.CheckDomainOrUrl(u);
            if (hit is not null)
            {
                risk += 45;
                feedHits.Add($"{u} -> {hit.FeedSource}");
                findings.Add($"CRITICAL: Embedded URL matched {hit.FeedSource} malware feed: {u}");
            }
            if (u.Contains("xn--", StringComparison.OrdinalIgnoreCase))
            {
                risk += 20;
                findings.Add($"Punycode/IDN homograph URL detected: {u}");
            }
        }

        if (Regex.IsMatch(bodySection, "filename=\"?[^\"\\r\\n]+\\.(exe|scr|js|vbs|hta|iso|lnk|bat|ps1)\"?", RegexOptions.IgnoreCase))
        {
            risk += 35;
            findings.Add("Dangerous executable/script attachment extension detected in MIME headers.");
        }

        risk = Math.Clamp(risk, 0, 100);
        string verdict = risk >= 65 ? "CRITICAL — Likely Phishing / Malicious"
            : risk >= 30 ? "SUSPICIOUS — Inspect Carefully"
            : "Low Risk";

        if (findings.Count == 0)
            findings.Add("No header spoofing, authentication failures, or known malicious URLs detected.");

        return new EmailForensicsReport
        {
            FileName = fileName,
            FromHeader = string.IsNullOrWhiteSpace(from) ? "(Missing)" : from,
            ReplyToHeader = string.IsNullOrWhiteSpace(replyTo) ? "(None)" : replyTo,
            ReturnPathHeader = string.IsNullOrWhiteSpace(returnPath) ? "(None)" : returnPath,
            Subject = string.IsNullOrWhiteSpace(subject) ? "(No Subject)" : subject,
            SpfStatus = spf,
            DkimStatus = dkim,
            DmarcStatus = dmarc,
            RiskScore = risk,
            Verdict = verdict,
            ReceivedHops = receivedHops,
            ExtractedUrls = urls,
            ThreatFeedHits = feedHits,
            Findings = findings,
            Summary = $"{verdict} (Score {risk}/100) · SPF={spf}, DKIM={dkim}, DMARC={dmarc} · {urls.Count} URL(s), {feedHits.Count} malware feed hit(s)."
        };
    }

    private static string MatchOrDefault(Regex rx, string input, string fallback)
    {
        var m = rx.Match(input ?? string.Empty);
        return m.Success ? m.Groups[1].Value.ToLowerInvariant() : fallback;
    }

    private static string ExtractEmailDomain(string header)
    {
        var m = EmailAddrRegex.Match(header ?? string.Empty);
        return m.Success ? m.Groups[1].Value.ToLowerInvariant() : string.Empty;
    }
}
