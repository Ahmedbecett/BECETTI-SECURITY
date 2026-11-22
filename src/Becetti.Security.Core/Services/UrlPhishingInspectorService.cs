using System.Globalization;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

public interface IUrlPhishingInspectorService
{
    Task<OperationResult<UrlInspectionReport>> InspectUrlAsync(string rawUrl, bool performLiveNetworkCheck = true, CancellationToken ct = default);
}

/// <summary>
/// Real Phishing & Homograph URL Inspector:
/// - Converts Internationalized Domain Names (IDN) to Punycode (xn--) and flags mixed-script / Cyrillic-Latin homograph spoofing
/// - Detects credential-in-URL (@), IP-literal hosting, excessive subdomains, and brand-impersonation lookalikes
/// - Performs a safe non-rendering HEAD probe to trace real HTTP redirects and inspect the live TLS/SSL X509 certificate
/// </summary>
public sealed class UrlPhishingInspectorService : IUrlPhishingInspectorService
{
    private static readonly string[] ImpersonatedBrands =
    {
        "paypal", "microsoft", "apple", "icloud", "google", "amazon", "netflix",
        "binance", "coinbase", "metamask", "facebook", "instagram", "whatsapp",
        "chase", "wellsfargo", "dhl", "fedex", "office365", "outlook", "github"
    };

    private static readonly string[] HighAbuseTlds =
    {
        ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".zip", ".mov", ".click", ".work", ".loan"
    };

    public async Task<OperationResult<UrlInspectionReport>> InspectUrlAsync(
        string rawUrl,
        bool performLiveNetworkCheck = true,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(rawUrl))
            return OperationResult<UrlInspectionReport>.Fail("Please enter a URL to inspect.", "INVALID_URL");

        var normalized = rawUrl.Trim();
        if (!normalized.StartsWith("http://", StringComparison.OrdinalIgnoreCase) &&
            !normalized.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            normalized = "https://" + normalized;
        }

        if (!Uri.TryCreate(normalized, UriKind.Absolute, out var uri) || string.IsNullOrWhiteSpace(uri.Host))
            return OperationResult<UrlInspectionReport>.Fail("Invalid URL format.", "INVALID_URL");

        var findings = new List<string>();
        int risk = 0;

        string host = uri.IdnHost;
        string unicodeHost = uri.DnsSafeHost;
        string punycodeHost = host;
        try
        {
            var idn = new IdnMapping();
            punycodeHost = idn.GetAscii(unicodeHost);
            unicodeHost = idn.GetUnicode(punycodeHost);
        }
        catch { }

        bool isHomograph = false;
        string homographReason = "No homograph/IDN spoofing detected.";

        // Check Punycode / Non-ASCII / Mixed Script Homograph
        bool hasNonAscii = unicodeHost.Any(c => c > 127);
        bool hasLatin = unicodeHost.Any(c => (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'));
        bool hasCyrillic = unicodeHost.Any(c => c >= '\u0400' && c <= '\u04FF');
        bool hasGreek = unicodeHost.Any(c => c >= '\u0370' && c <= '\u03FF');

        if (punycodeHost.Contains("xn--", StringComparison.OrdinalIgnoreCase))
        {
            if (hasLatin && (hasCyrillic || hasGreek))
            {
                isHomograph = true;
                homographReason = "CRITICAL: Mixed Latin + Cyrillic/Greek characters in Punycode domain (classic IDN Homograph attack!).";
                risk += 60;
                findings.Add(homographReason);
            }
            else if (hasNonAscii)
            {
                isHomograph = true;
                homographReason = $"Internationalized Punycode domain ({punycodeHost}) — verify carefully against lookalike spoofing.";
                risk += 25;
                findings.Add(homographReason);
            }
        }

        if (!uri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase))
        {
            risk += 20;
            findings.Add("Uses unencrypted HTTP (no TLS protection).");
        }

        if (!string.IsNullOrEmpty(uri.UserInfo))
        {
            risk += 45;
            findings.Add("Contains embedded '@' user-info prefix — classic phishing trick to disguise the true destination host.");
        }

        if (IPAddress.TryParse(punycodeHost.Trim('[', ']'), out _))
        {
            risk += 35;
            findings.Add("Uses a raw IP address instead of a registered domain name.");
        }

        var labels = punycodeHost.Split('.', StringSplitOptions.RemoveEmptyEntries);
        if (labels.Length >= 5)
        {
            risk += 20;
            findings.Add($"Excessive subdomain depth ({labels.Length} labels) often used in phishing links.");
        }

        if (HighAbuseTlds.Any(tld => punycodeHost.EndsWith(tld, StringComparison.OrdinalIgnoreCase)))
        {
            risk += 15;
            findings.Add("Top-level domain has elevated phishing/abuse prevalence.");
        }

        // Brand impersonation check (brand appears in subdomain or hyphenated lookalike, not official root)
        if (labels.Length >= 2)
        {
            var registrable = $"{labels[^2]}.{labels[^1]}".ToLowerInvariant();
            var subdomainPart = string.Join('.', labels.Take(labels.Length - 2)).ToLowerInvariant();
            foreach (var brand in ImpersonatedBrands)
            {
                bool inSub = subdomainPart.Contains(brand);
                bool hyphenLookalike = labels[^2].Contains(brand, StringComparison.OrdinalIgnoreCase) &&
                                       !labels[^2].Equals(brand, StringComparison.OrdinalIgnoreCase);
                if (inSub || hyphenLookalike)
                {
                    risk += 35;
                    findings.Add($"Possible brand impersonation of '{brand}' on third-party domain '{registrable}'.");
                    break;
                }
            }
        }

        // Live safe HEAD probe for TLS certificate + Redirect Chain
        var redirects = new List<string> { uri.ToString() };
        bool tlsInspected = false;
        bool tlsValid = false;
        string tlsSubject = string.Empty;
        string tlsIssuer = string.Empty;
        DateTimeOffset? tlsNotAfter = null;
        int tlsDaysRemaining = 0;

        if (performLiveNetworkCheck)
        {
            try
            {
                using var handler = new SocketsHttpHandler
                {
                    AllowAutoRedirect = false,
                    ConnectTimeout = TimeSpan.FromSeconds(6),
                    SslOptions = new SslClientAuthenticationOptions
                    {
                        RemoteCertificateValidationCallback = (_, cert, _, sslErrors) =>
                        {
                            tlsInspected = true;
                            tlsValid = sslErrors == SslPolicyErrors.None;
                            if (cert is not null)
                            {
                                using var x509 = new X509Certificate2(cert);
                                tlsSubject = x509.Subject;
                                tlsIssuer = x509.Issuer;
                                tlsNotAfter = new DateTimeOffset(x509.NotAfter.ToUniversalTime());
                                tlsDaysRemaining = (int)(tlsNotAfter.Value - DateTimeOffset.UtcNow).TotalDays;
                            }
                            return true; // Inspect only, never execute content
                        }
                    }
                };

                using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(8) };
                client.DefaultRequestHeaders.UserAgent.ParseAdd("BECETTI-SECURITY-URL-Inspector/1.0");

                var current = uri;
                for (int hop = 0; hop < 5; hop++)
                {
                    using var req = new HttpRequestMessage(HttpMethod.Head, current);
                    using var resp = await client.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
                    int code = (int)resp.StatusCode;
                    if (code is >= 300 and < 400 && resp.Headers.Location is not null)
                    {
                        var next = resp.Headers.Location.IsAbsoluteUri
                            ? resp.Headers.Location
                            : new Uri(current, resp.Headers.Location);
                        redirects.Add(next.ToString());
                        current = next;
                    }
                    else
                    {
                        break;
                    }
                }

                if (tlsInspected && !tlsValid)
                {
                    risk += 40;
                    findings.Add("TLS/SSL certificate validation failed (untrusted, mismatched, or expired certificate).");
                }
                if (redirects.Count > 3)
                {
                    risk += 15;
                    findings.Add($"Long redirect chain ({redirects.Count - 1} redirects) masking final destination.");
                }
            }
            catch (Exception ex)
            {
                findings.Add($"Live network/TLS probe skipped or unreachable: {ex.Message}");
            }
        }

        risk = Math.Clamp(risk, 0, 100);
        string riskLevel = risk >= 65 ? "Critical" : risk >= 40 ? "High" : risk >= 20 ? "Medium" : "Low";
        if (findings.Count == 0)
            findings.Add("No phishing, homograph, or TLS anomalies detected.");

        var report = new UrlInspectionReport
        {
            InspectedAt = DateTimeOffset.UtcNow,
            OriginalUrl = uri.ToString(),
            Host = unicodeHost,
            PunycodeHost = punycodeHost,
            UsesHttps = uri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase),
            IsHomographSuspected = isHomograph,
            HomographReason = homographReason,
            RedirectChain = redirects,
            TlsInspected = tlsInspected,
            TlsValid = tlsValid,
            TlsSubject = tlsSubject,
            TlsIssuer = tlsIssuer,
            TlsNotAfter = tlsNotAfter,
            TlsDaysRemaining = tlsDaysRemaining,
            RiskScore = risk,
            RiskLevel = riskLevel,
            Findings = findings
        };

        return OperationResult<UrlInspectionReport>.Ok(
            report,
            $"URL Risk: {riskLevel} ({risk}/100) · Host: {punycodeHost}");
    }
}
