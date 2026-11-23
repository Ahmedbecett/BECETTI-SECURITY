using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

public interface IDomainHostingIntelService
{
    Task<OperationResult<CompleteDomainHostingReport>> RunCompleteAuditAsync(string targetInput, bool probeHostingPorts = true, CancellationToken ct = default);
    Task<OperationResult<string>> ExportHtmlReportAsync(CompleteDomainHostingReport report, string outputPath, CancellationToken ct = default);
    Task<OperationResult<string>> ExportJsonReportAsync(CompleteDomainHostingReport report, string outputPath, CancellationToken ct = default);
}

/// <summary>
/// Global Domain, Hosting, DNS &amp; IP Security Intelligence Suite (100% REAL live protocols, ZERO API keys):
///   - Full DNS Record Inspector (A, AAAA, MX, NS, TXT, CNAME, SOA, CAA, DS) + DNSSEC via DoH
///   - 4-Resolver Global DNS Propagation Check (Cloudflare, Google, Quad9, DNS.SB)
///   - Official IANA RDAP / WHOIS Domain &amp; IP Intelligence (Registrar, Expiry Countdown, EPP Locks)
///   - Real SslStream TLS 1.2/1.3 Certificate &amp; HTTP Security Headers Audit (Grade A+ to F)
///   - Email Domain Anti-Spoofing Auditor (MX, SPF, DMARC, DKIM selectors, BIMI, MTA-STS)
///   - Hosting IP Deep Intel (PTR, GeoIP/ASN/Org, 5 live DNSBL Blacklists, abuse.ch feeds, 11-Port Probe)
///   - Certificate Transparency Subdomain Discovery (crt.sh)
/// </summary>
public sealed class DomainHostingIntelService : IDomainHostingIntelService
{
    private static readonly string[] DnsRecordTypes = { "A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA", "DS" };
    private static readonly string[] DkimSelectors = { "default", "google", "selector1", "selector2", "k1", "s1", "dkim" };
    private static readonly string[] DnsblZones =
    {
        "zen.spamhaus.org",
        "bl.spamcop.net",
        "b.barracudacentral.org",
        "dnsbl.sorbs.net",
        "cbl.abuseat.org"
    };

    private static readonly (int Port, string Name, string HighRiskNote)[] HostingPorts =
    {
        (21, "FTP", "Unencrypted FTP exposed — prefer SFTP/FTPS"),
        (22, "SSH", "SSH exposed — restrict by firewall / key-only auth"),
        (25, "SMTP", "Mail relay port open"),
        (53, "DNS", "DNS service exposed"),
        (80, "HTTP", "Web HTTP"),
        (443, "HTTPS", "Web HTTPS"),
        (3306, "MySQL", "HIGH RISK: MySQL database port publicly reachable!"),
        (3389, "RDP", "HIGH RISK: Windows RDP publicly reachable!"),
        (5432, "PostgreSQL", "HIGH RISK: PostgreSQL database port publicly reachable!"),
        (8080, "HTTP-Alt", "Alternate web/proxy port"),
        (8443, "HTTPS-Alt", "Alternate HTTPS/admin panel port")
    };

    private readonly HttpClient _http;
    private readonly IThreatFeedService _feeds;

    public DomainHostingIntelService(HttpClient http, IThreatFeedService feeds)
    {
        _http = http;
        _feeds = feeds;
    }

    public async Task<OperationResult<CompleteDomainHostingReport>> RunCompleteAuditAsync(
        string targetInput, bool probeHostingPorts = true, CancellationToken ct = default)
    {
        var (normalized, isIp, error) = NormalizeTarget(targetInput);
        if (!string.IsNullOrEmpty(error))
            return OperationResult<CompleteDomainHostingReport>.Fail(error);

        if (isIp)
        {
            var ipIntel = await AuditIpAndHostingAsync(normalized, probeHostingPorts, ct).ConfigureAwait(false);
            var ipRdap = await QueryRdapAsync(normalized, isIp: true, ct).ConfigureAwait(false);
            int ipScore = ipIntel.IsThreatFeedHit ? 20 : Math.Max(40, 100 - (ipIntel.BlacklistHitCount * 20));
            string ipGrade = ScoreToGrade(ipScore);
            var ipSummary = $"IP Audit ({normalized}): {ipIntel.Organization} ({ipIntel.Asn}, {ipIntel.Country}) · {ipIntel.BlacklistHitCount} DNSBL hit(s) · Grade {ipGrade}";

            return OperationResult<CompleteDomainHostingReport>.Ok(new CompleteDomainHostingReport
            {
                QueryInput = targetInput,
                NormalizedTarget = normalized,
                IsIpOnlyQuery = true,
                AuditedAt = DateTimeOffset.UtcNow,
                Rdap = ipRdap,
                IpHosting = ipIntel,
                OverallScore = ipScore,
                OverallGrade = ipGrade,
                Summary = ipSummary
            }, ipSummary);
        }

        // Domain audit: run DNS, Propagation, RDAP, SSL/Hosting, Email Security, and CT Subdomains concurrently
        var dnsTask = QueryAllDnsRecordsAsync(normalized, ct);
        var propTask = CheckGlobalPropagationAsync(normalized, ct);
        var rdapTask = QueryRdapAsync(normalized, isIp: false, ct);
        var sslTask = AuditSslAndHostingHeadersAsync(normalized, ct);
        var emailTask = AuditEmailSecurityAsync(normalized, ct);
        var ctTask = QueryCrtShSubdomainsAsync(normalized, ct);

        await Task.WhenAll(dnsTask, propTask, rdapTask, sslTask, emailTask, ctTask).ConfigureAwait(false);

        var dnsRecords = await dnsTask.ConfigureAwait(false);
        var propagation = await propTask.ConfigureAwait(false);
        var rdap = await rdapTask.ConfigureAwait(false);
        var sslHosting = await sslTask.ConfigureAwait(false);
        var emailSec = await emailTask.ConfigureAwait(false);
        var subdomains = await ctTask.ConfigureAwait(false);

        bool dnssec = dnsRecords.Any(r => r.RecordType == "DS") || propagation.Any(p => p.DnssecValidated);

        // Pick primary IPv4 (or IPv6) from DNS A records for Hosting/IP/DNSBL/Port inspection
        var primaryIp = dnsRecords.FirstOrDefault(r => r.RecordType == "A")?.Data
                     ?? dnsRecords.FirstOrDefault(r => r.RecordType == "AAAA")?.Data
                     ?? string.Empty;

        IpAndHostingIntel ipHosting = !string.IsNullOrWhiteSpace(primaryIp)
            ? await AuditIpAndHostingAsync(primaryIp, probeHostingPorts, ct).ConfigureAwait(false)
            : new IpAndHostingIntel { Summary = "No A/AAAA record resolved for this domain." };

        // Also check the domain itself against local abuse.ch URLhaus feed
        var domainFeedHit = _feeds.CheckDomainOrUrl(normalized);
        if (domainFeedHit is not null && !ipHosting.IsThreatFeedHit)
        {
            ipHosting = new IpAndHostingIntel
            {
                IpAddress = ipHosting.IpAddress,
                ReversePtr = ipHosting.ReversePtr,
                Country = ipHosting.Country,
                City = ipHosting.City,
                Asn = ipHosting.Asn,
                Organization = ipHosting.Organization,
                Isp = ipHosting.Isp,
                IsThreatFeedHit = true,
                AbuseThreatFeedMatch = $"CRITICAL MATCH: Domain listed in {domainFeedHit.FeedSource} ({domainFeedHit.Mitre.TechniqueId})",
                BlacklistHitCount = ipHosting.BlacklistHitCount,
                DnsblResults = ipHosting.DnsblResults,
                PortProbes = ipHosting.PortProbes,
                Summary = ipHosting.Summary
            };
        }

        int overallScore = ComputeOverallDomainScore(sslHosting, emailSec, ipHosting, dnssec);
        string overallGrade = ScoreToGrade(overallScore);

        var summary =
            $"{normalized} · Overall Grade {overallGrade} ({overallScore}/100) · " +
            $"Hosting {sslHosting.HostingGrade} · Email {emailSec.EmailGrade} · " +
            $"DNS {dnsRecords.Count} records ({(dnssec ? "DNSSEC ON" : "DNSSEC OFF")}) · " +
            $"IP {ipHosting.IpAddress} ({ipHosting.Organization}) · {subdomains.Count} CT subdomain(s).";

        return OperationResult<CompleteDomainHostingReport>.Ok(new CompleteDomainHostingReport
        {
            QueryInput = targetInput,
            NormalizedTarget = normalized,
            IsIpOnlyQuery = false,
            AuditedAt = DateTimeOffset.UtcNow,
            DnsRecords = dnsRecords,
            PropagationChecks = propagation,
            DnssecEnabled = dnssec,
            Rdap = rdap,
            SslHosting = sslHosting,
            EmailSecurity = emailSec,
            IpHosting = ipHosting,
            Subdomains = subdomains,
            OverallScore = overallScore,
            OverallGrade = overallGrade,
            Summary = summary
        }, summary);
    }

    // -------------------------------------------------------------------------
    //  1. DNS Records & 4-Resolver Global Propagation (Live DoH)
    // -------------------------------------------------------------------------

    private async Task<List<DnsRecordItem>> QueryAllDnsRecordsAsync(string domain, CancellationToken ct)
    {
        var tasks = DnsRecordTypes.Select(t => QueryDohRecordsAsync("https://cloudflare-dns.com/dns-query", domain, t, ct));
        var results = await Task.WhenAll(tasks).ConfigureAwait(false);
        var all = new List<DnsRecordItem>();
        foreach (var (records, _) in results) all.AddRange(records);
        return all;
    }

    private async Task<List<DnsPropagationCheck>> CheckGlobalPropagationAsync(string domain, CancellationToken ct)
    {
        var resolvers = new[]
        {
            ("Cloudflare", "1.1.1.1", "https://cloudflare-dns.com/dns-query"),
            ("Google DNS", "8.8.8.8", "https://dns.google/resolve"),
            ("Quad9 Security", "9.9.9.9", "https://dns.quad9.net:5053/dns-query"),
            ("DNS.SB Global", "185.222.222.222", "https://doh.dns.sb/dns-query")
        };

        var tasks = resolvers.Select(async r =>
        {
            var sw = Stopwatch.StartNew();
            var (recs, ad) = await QueryDohRecordsAsync(r.Item3, domain, "A", ct).ConfigureAwait(false);
            sw.Stop();
            return new DnsPropagationCheck
            {
                ResolverName = r.Item1,
                ResolverIp = r.Item2,
                Succeeded = recs.Count > 0,
                DnssecValidated = ad,
                ResolvedValues = recs.Count > 0 ? string.Join(", ", recs.Select(x => x.Data).Distinct().Take(4)) : "No A record",
                LatencyMs = sw.ElapsedMilliseconds
            };
        });

        return (await Task.WhenAll(tasks).ConfigureAwait(false)).ToList();
    }

    private async Task<(List<DnsRecordItem> Records, bool AdFlag)> QueryDohRecordsAsync(
        string dohEndpoint, string name, string type, CancellationToken ct)
    {
        try
        {
            var url = $"{dohEndpoint}?name={Uri.EscapeDataString(name)}&type={Uri.EscapeDataString(type)}";
            using var req = new HttpRequestMessage(HttpMethod.Get, url);
            req.Headers.Accept.ParseAdd("application/dns-json");
            req.Headers.UserAgent.ParseAdd("BECETTI-SECURITY/1.0");

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(7));
            using var resp = await _http.SendAsync(req, cts.Token).ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode) return (new List<DnsRecordItem>(), false);

            var json = await resp.Content.ReadAsStringAsync(cts.Token).ConfigureAwait(false);
            return ParseDohJson(json, type);
        }
        catch { return (new List<DnsRecordItem>(), false); }
    }

    internal static (List<DnsRecordItem> Records, bool AdFlag) ParseDohJson(string json, string requestedType)
    {
        var list = new List<DnsRecordItem>();
        bool ad = false;
        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            ad = root.TryGetProperty("AD", out var adEl) && adEl.ValueKind == JsonValueKind.True;

            if (root.TryGetProperty("Answer", out var ans) && ans.ValueKind == JsonValueKind.Array)
            {
                foreach (var a in ans.EnumerateArray())
                {
                    var name = a.TryGetProperty("name", out var nEl) ? nEl.GetString() ?? "" : "";
                    int ttl = a.TryGetProperty("TTL", out var tEl) && tEl.TryGetInt32(out var tv) ? tv : 0;
                    var data = a.TryGetProperty("data", out var dEl) ? dEl.GetString() ?? "" : "";
                    int typeCode = a.TryGetProperty("type", out var tyEl) && tyEl.TryGetInt32(out var tyv) ? tyv : 0;
                    string typeLabel = MapDnsTypeCode(typeCode, requestedType);

                    if (!string.IsNullOrWhiteSpace(data))
                    {
                        list.Add(new DnsRecordItem
                        {
                            RecordType = typeLabel,
                            Name = name.TrimEnd('.'),
                            Ttl = ttl,
                            Data = data.Trim('"')
                        });
                    }
                }
            }
        }
        catch { }
        return (list, ad);
    }

    private static string MapDnsTypeCode(int code, string fallback) => code switch
    {
        1 => "A", 2 => "NS", 5 => "CNAME", 6 => "SOA", 12 => "PTR",
        15 => "MX", 16 => "TXT", 28 => "AAAA", 33 => "SRV", 43 => "DS", 257 => "CAA",
        _ => fallback
    };

    // -------------------------------------------------------------------------
    //  2. Official IANA RDAP / WHOIS Intelligence
    // -------------------------------------------------------------------------

    private async Task<DomainRdapInfo> QueryRdapAsync(string target, bool isIp, CancellationToken ct)
    {
        try
        {
            var url = isIp ? $"https://rdap.org/ip/{Uri.EscapeDataString(target)}" : $"https://rdap.org/domain/{Uri.EscapeDataString(target)}";
            using var req = new HttpRequestMessage(HttpMethod.Get, url);
            req.Headers.Accept.ParseAdd("application/rdap+json");
            req.Headers.UserAgent.ParseAdd("BECETTI-SECURITY/1.0");

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(10));
            using var resp = await _http.SendAsync(req, cts.Token).ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode)
                return new DomainRdapInfo { Available = false, DomainName = target, Summary = $"RDAP unavailable (HTTP {(int)resp.StatusCode})." };

            var json = await resp.Content.ReadAsStringAsync(cts.Token).ConfigureAwait(false);
            return ParseRdapJson(json, target);
        }
        catch (Exception ex)
        {
            return new DomainRdapInfo { Available = false, DomainName = target, Summary = $"RDAP query error: {ex.Message}" };
        }
    }

    internal static DomainRdapInfo ParseRdapJson(string json, string target)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            string ldhName = root.TryGetProperty("ldhName", out var l) ? l.GetString() ?? target : target;
            string registrar = "Unknown";
            DateTimeOffset? created = null, updated = null, expires = null;
            var statuses = new List<string>();
            var nameservers = new List<string>();

            if (root.TryGetProperty("status", out var st) && st.ValueKind == JsonValueKind.Array)
            {
                foreach (var s in st.EnumerateArray())
                    if (s.GetString() is string sv) statuses.Add(sv);
            }

            if (root.TryGetProperty("nameservers", out var nss) && nss.ValueKind == JsonValueKind.Array)
            {
                foreach (var ns in nss.EnumerateArray())
                    if (ns.TryGetProperty("ldhName", out var n) && n.GetString() is string nv)
                        nameservers.Add(nv.ToLowerInvariant());
            }

            if (root.TryGetProperty("events", out var evs) && evs.ValueKind == JsonValueKind.Array)
            {
                foreach (var ev in evs.EnumerateArray())
                {
                    var action = ev.TryGetProperty("eventAction", out var a) ? a.GetString() ?? "" : "";
                    var dateStr = ev.TryGetProperty("eventDate", out var d) ? d.GetString() ?? "" : "";
                    if (!DateTimeOffset.TryParse(dateStr, out var dt)) continue;

                    if (action.Equals("registration", StringComparison.OrdinalIgnoreCase)) created = dt;
                    else if (action.Equals("expiration", StringComparison.OrdinalIgnoreCase)) expires = dt;
                    else if (action.Equals("last changed", StringComparison.OrdinalIgnoreCase)) updated = dt;
                }
            }

            if (root.TryGetProperty("entities", out var ents) && ents.ValueKind == JsonValueKind.Array)
            {
                foreach (var ent in ents.EnumerateArray())
                {
                    bool isRegistrar = ent.TryGetProperty("roles", out var roles) &&
                                       roles.ValueKind == JsonValueKind.Array &&
                                       roles.EnumerateArray().Any(r => string.Equals(r.GetString(), "registrar", StringComparison.OrdinalIgnoreCase));
                    if (!isRegistrar) continue;

                    if (ent.TryGetProperty("vcardArray", out var vc) && vc.ValueKind == JsonValueKind.Array && vc.GetArrayLength() >= 2)
                    {
                        foreach (var prop in vc[1].EnumerateArray())
                        {
                            if (prop.ValueKind == JsonValueKind.Array && prop.GetArrayLength() >= 4 &&
                                string.Equals(prop[0].GetString(), "fn", StringComparison.OrdinalIgnoreCase))
                            {
                                registrar = prop[3].GetString() ?? registrar;
                                break;
                            }
                        }
                    }
                }
            }

            int? daysLeft = expires.HasValue ? (int)Math.Ceiling((expires.Value - DateTimeOffset.UtcNow).TotalDays) : null;
            string expText = expires.HasValue ? $"{expires.Value:yyyy-MM-dd} ({daysLeft}d left)" : "Unknown";
            return new DomainRdapInfo
            {
                Available = true,
                DomainName = ldhName,
                Registrar = registrar,
                CreatedDate = created,
                UpdatedDate = updated,
                ExpirationDate = expires,
                DaysUntilExpiry = daysLeft,
                StatusFlags = statuses,
                NameServers = nameservers,
                Summary = $"Registrar: {registrar} · Expires: {expText} · {nameservers.Count} NS · {statuses.Count} EPP status flag(s)."
            };
        }
        catch
        {
            return new DomainRdapInfo { Available = false, DomainName = target, Summary = "Could not parse RDAP JSON." };
        }
    }

    // -------------------------------------------------------------------------
    //  3. Real SSL/TLS Handshake & Hosting HTTP Security Headers Audit
    // -------------------------------------------------------------------------

    private async Task<SslAndHostingAudit> AuditSslAndHostingHeadersAsync(string domain, CancellationToken ct)
    {
        bool sslOk = false;
        string tlsProto = "Unavailable", subject = "", issuer = "", thumb = "";
        DateTimeOffset? validFrom = null, validTo = null;
        int? daysLeft = null;
        var sans = new List<string>();

        // Real TLS handshake on port 443
        try
        {
            using var tcp = new TcpClient();
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(6));
            await tcp.ConnectAsync(domain, 443, cts.Token).ConfigureAwait(false);
            using var ssl = new SslStream(tcp.GetStream(), false, (_, _, _, _) => true);
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost = domain }, cts.Token).ConfigureAwait(false);

            sslOk = true;
            tlsProto = ssl.SslProtocol.ToString();
            if (ssl.RemoteCertificate is not null)
            {
                using var cert = new X509Certificate2(ssl.RemoteCertificate);
                subject = cert.Subject;
                issuer = cert.Issuer;
                validFrom = new DateTimeOffset(cert.NotBefore.ToUniversalTime());
                validTo = new DateTimeOffset(cert.NotAfter.ToUniversalTime());
                daysLeft = (int)Math.Ceiling((validTo.Value - DateTimeOffset.UtcNow).TotalDays);
                thumb = cert.Thumbprint ?? string.Empty;

                foreach (var ext in cert.Extensions)
                {
                    if (ext.Oid?.Value == "2.5.29.17") // Subject Alternative Name
                    {
                        var formatted = ext.Format(false);
                        foreach (Match m in Regex.Matches(formatted, @"DNS Name=([^,\s]+)"))
                            sans.Add(m.Groups[1].Value);
                    }
                }
            }
        }
        catch { }

        // Check HTTP -> HTTPS redirect
        bool redirectsToHttps = false;
        try
        {
            using var noRedirectHandler = new HttpClientHandler { AllowAutoRedirect = false };
            using var client = new HttpClient(noRedirectHandler) { Timeout = TimeSpan.FromSeconds(6) };
            using var hResp = await client.GetAsync($"http://{domain}/", ct).ConfigureAwait(false);
            var loc = hResp.Headers.Location?.ToString() ?? string.Empty;
            redirectsToHttps = (int)hResp.StatusCode is >= 300 and < 400 &&
                               loc.StartsWith("https://", StringComparison.OrdinalIgnoreCase);
        }
        catch { }

        // Inspect HTTPS response security headers & hosting stack
        int statusCode = 0;
        string serverBanner = "Hidden", poweredBy = "Hidden", cdnGuess = "Direct / Self-Hosted";
        var headerChecks = new List<SecurityHeaderCheck>();
        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, $"https://{domain}/");
            req.Headers.UserAgent.ParseAdd("BECETTI-SECURITY-Auditor/1.0");
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(8));
            using var resp = await _http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, cts.Token).ConfigureAwait(false);
            statusCode = (int)resp.StatusCode;

            string GetHdr(string name)
            {
                if (resp.Headers.TryGetValues(name, out var v)) return string.Join("; ", v);
                if (resp.Content.Headers.TryGetValues(name, out var cv)) return string.Join("; ", cv);
                return string.Empty;
            }

            serverBanner = string.IsNullOrWhiteSpace(GetHdr("Server")) ? "Hidden" : GetHdr("Server");
            poweredBy = string.IsNullOrWhiteSpace(GetHdr("X-Powered-By")) ? "Hidden" : GetHdr("X-Powered-By");
            cdnGuess = DetectHostingOrCdn(serverBanner, GetHdr("CF-Ray"), GetHdr("X-Vercel-Id"), GetHdr("X-Amz-Cf-Id"), GetHdr("Via"));

            var requiredHeaders = new (string Name, string Rec)[]
            {
                ("Strict-Transport-Security", "Add HSTS (max-age=31536000; includeSubDomains; preload)"),
                ("Content-Security-Policy", "Add CSP to block XSS and unauthorized script injection"),
                ("X-Frame-Options", "Add X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking"),
                ("X-Content-Type-Options", "Add X-Content-Type-Options: nosniff"),
                ("Referrer-Policy", "Add Referrer-Policy: strict-origin-when-cross-origin"),
                ("Permissions-Policy", "Add Permissions-Policy to restrict camera/mic/geolocation APIs")
            };

            foreach (var (hName, rec) in requiredHeaders)
            {
                var val = GetHdr(hName);
                headerChecks.Add(new SecurityHeaderCheck
                {
                    HeaderName = hName,
                    Present = !string.IsNullOrWhiteSpace(val),
                    Value = val.Length > 100 ? val[..100] + "…" : val,
                    Recommendation = rec
                });
            }
        }
        catch { }

        int score = 0;
        if (sslOk) score += 30;
        if (tlsProto.Contains("Tls13", StringComparison.OrdinalIgnoreCase) || tlsProto.Contains("Tls12", StringComparison.OrdinalIgnoreCase)) score += 10;
        if (daysLeft is > 14) score += 10;
        if (redirectsToHttps) score += 10;
        score += headerChecks.Count(h => h.Present) * 6; // up to 36
        if (poweredBy == "Hidden") score += 4;
        score = Math.Clamp(score, 0, 100);
        string grade = ScoreToGrade(score);

        return new SslAndHostingAudit
        {
            SslReachable = sslOk,
            TlsProtocol = tlsProto,
            CertSubject = subject,
            CertIssuer = issuer,
            ValidFrom = validFrom,
            ValidTo = validTo,
            DaysRemaining = daysLeft,
            Thumbprint = thumb,
            SubjectAltNames = sans.Take(20).ToList(),
            HttpRedirectsToHttps = redirectsToHttps,
            HttpStatusCode = statusCode,
            ServerBanner = serverBanner,
            PoweredByBanner = poweredBy,
            DetectedCdnOrHost = cdnGuess,
            HostingSecurityScore = score,
            HostingGrade = grade,
            HeaderChecks = headerChecks,
            Summary = $"Grade {grade} ({score}/100) · TLS: {tlsProto} ({(daysLeft.HasValue ? $"{daysLeft}d left" : "N/A")}) · Host/CDN: {cdnGuess} · {headerChecks.Count(h => h.Present)}/{headerChecks.Count} security headers."
        };
    }

    private static string DetectHostingOrCdn(string server, string cfRay, string vercelId, string cfId, string via)
    {
        if (!string.IsNullOrWhiteSpace(cfRay) || server.Contains("cloudflare", StringComparison.OrdinalIgnoreCase)) return "Cloudflare CDN / WAF";
        if (!string.IsNullOrWhiteSpace(vercelId) || server.Contains("vercel", StringComparison.OrdinalIgnoreCase)) return "Vercel Edge Network";
        if (!string.IsNullOrWhiteSpace(cfId) || via.Contains("cloudfront", StringComparison.OrdinalIgnoreCase)) return "AWS CloudFront";
        if (server.Contains("gws", StringComparison.OrdinalIgnoreCase) || server.Contains("GSE", StringComparison.OrdinalIgnoreCase)) return "Google Cloud / Frontend";
        if (server.Contains("nginx", StringComparison.OrdinalIgnoreCase)) return "NGINX Web Server";
        if (server.Contains("apache", StringComparison.OrdinalIgnoreCase)) return "Apache HTTP Server";
        if (server.Contains("litespeed", StringComparison.OrdinalIgnoreCase)) return "LiteSpeed Enterprise";
        if (server.Contains("Microsoft-IIS", StringComparison.OrdinalIgnoreCase)) return "Microsoft IIS";
        return server != "Hidden" ? server : "Protected / Hidden Stack";
    }

    // -------------------------------------------------------------------------
    //  4. Email Domain Anti-Spoofing Auditor (MX, SPF, DMARC, DKIM, BIMI, MTA-STS)
    // -------------------------------------------------------------------------

    private async Task<EmailDomainSecurityAudit> AuditEmailSecurityAsync(string domain, CancellationToken ct)
    {
        var mxTask = QueryDohRecordsAsync("https://cloudflare-dns.com/dns-query", domain, "MX", ct);
        var txtTask = QueryDohRecordsAsync("https://cloudflare-dns.com/dns-query", domain, "TXT", ct);
        var dmarcTask = QueryDohRecordsAsync("https://cloudflare-dns.com/dns-query", $"_dmarc.{domain}", "TXT", ct);
        var mtaStsTask = QueryDohRecordsAsync("https://cloudflare-dns.com/dns-query", $"_mta-sts.{domain}", "TXT", ct);
        var bimiTask = QueryDohRecordsAsync("https://cloudflare-dns.com/dns-query", $"default._bimi.{domain}", "TXT", ct);

        var dkimTasks = DkimSelectors.Select(async sel =>
        {
            var (recs, _) = await QueryDohRecordsAsync("https://cloudflare-dns.com/dns-query", $"{sel}._domainkey.{domain}", "TXT", ct).ConfigureAwait(false);
            return recs.Any(r => r.Data.Contains("v=DKIM1", StringComparison.OrdinalIgnoreCase) || r.Data.Contains("p=", StringComparison.OrdinalIgnoreCase))
                ? sel : null;
        });

        await Task.WhenAll(mxTask, txtTask, dmarcTask, mtaStsTask, bimiTask).ConfigureAwait(false);
        var dkimFound = (await Task.WhenAll(dkimTasks).ConfigureAwait(false)).Where(s => s is not null).Cast<string>().ToList();

        var mxList = (await mxTask.ConfigureAwait(false)).Records.Select(r => r.Data).ToList();
        var txtList = (await txtTask.ConfigureAwait(false)).Records.Select(r => r.Data).ToList();
        var dmarcRec = (await dmarcTask.ConfigureAwait(false)).Records.Select(r => r.Data).FirstOrDefault(d => d.Contains("v=DMARC1", StringComparison.OrdinalIgnoreCase));
        bool hasMtaSts = (await mtaStsTask.ConfigureAwait(false)).Records.Any(r => r.Data.Contains("v=STSv1", StringComparison.OrdinalIgnoreCase));
        bool hasBimi = (await bimiTask.ConfigureAwait(false)).Records.Any(r => r.Data.Contains("v=BIMI1", StringComparison.OrdinalIgnoreCase));

        return EvaluateEmailSecurity(domain, mxList, txtList, dmarcRec, dkimFound, hasMtaSts, hasBimi);
    }

    internal static EmailDomainSecurityAudit EvaluateEmailSecurity(
        string domain,
        IReadOnlyList<string> mxRecords,
        IReadOnlyList<string> rootTxtRecords,
        string? dmarcRecord,
        IReadOnlyList<string> foundDkimSelectors,
        bool hasMtaSts,
        bool hasBimi)
    {
        var spf = rootTxtRecords.FirstOrDefault(t => t.StartsWith("v=spf1", StringComparison.OrdinalIgnoreCase));
        bool hasSpf = !string.IsNullOrWhiteSpace(spf);
        bool hasDmarc = !string.IsNullOrWhiteSpace(dmarcRecord);

        var recs = new List<string>();
        int score = 0;

        string spfAssess;
        if (!hasSpf)
        {
            spfAssess = "Missing — attackers can spoof email from this domain.";
            recs.Add($"Add TXT record: v=spf1 mx -all");
        }
        else if (spf!.Contains("-all", StringComparison.OrdinalIgnoreCase))
        {
            spfAssess = "Strong (-all hard fail enforced).";
            score += 35;
        }
        else if (spf.Contains("~all", StringComparison.OrdinalIgnoreCase))
        {
            spfAssess = "Moderate (~all soft fail — consider tightening to -all).";
            score += 25;
        }
        else
        {
            spfAssess = "Weak (missing -all/~all enforcement).";
            score += 10;
            recs.Add("Tighten SPF record to end with '-all' or '~all'.");
        }

        string dmarcAssess;
        if (!hasDmarc)
        {
            dmarcAssess = "Missing — no spoofing protection policy published.";
            recs.Add($"Add _dmarc.{domain} TXT: v=DMARC1; p=quarantine; rua=mailto:dmarc@{domain}");
        }
        else if (dmarcRecord!.Contains("p=reject", StringComparison.OrdinalIgnoreCase))
        {
            dmarcAssess = "Maximum Protection (p=reject enforced).";
            score += 40;
        }
        else if (dmarcRecord.Contains("p=quarantine", StringComparison.OrdinalIgnoreCase))
        {
            dmarcAssess = "Strong Protection (p=quarantine).";
            score += 30;
        }
        else
        {
            dmarcAssess = "Monitoring Only (p=none) — does not block spoofed email yet.";
            score += 15;
            recs.Add("Upgrade DMARC policy from p=none to p=quarantine or p=reject.");
        }

        if (foundDkimSelectors.Count > 0) score += 15;
        else recs.Add("Publish cryptographic DKIM keys via your mail provider.");

        if (hasMtaSts) score += 5;
        if (hasBimi) score += 5;

        score = Math.Clamp(score, 0, 100);
        string grade = ScoreToGrade(score);

        string mxJoined = string.Join(" ", mxRecords).ToLowerInvariant();
        string provider = mxJoined.Contains("google") || mxJoined.Contains("aspmx") ? "Google Workspace"
            : mxJoined.Contains("outlook.com") || mxJoined.Contains("protection.outlook") ? "Microsoft 365 / Exchange Online"
            : mxJoined.Contains("protonmail") ? "Proton Mail"
            : mxJoined.Contains("zoho") ? "Zoho Mail"
            : mxJoined.Contains("cloudflare") ? "Cloudflare Email Routing"
            : mxJoined.Contains("mailgun") ? "Mailgun"
            : (mxRecords.Count == 0 ? "No MX Configured" : "Custom Mail Server");

        return new EmailDomainSecurityAudit
        {
            Domain = domain,
            MailProviderGuess = provider,
            MxRecords = mxRecords,
            HasSpf = hasSpf,
            SpfRecord = spf ?? "(Not Found)",
            SpfPolicyAssessment = spfAssess,
            HasDmarc = hasDmarc,
            DmarcRecord = dmarcRecord ?? "(Not Found)",
            DmarcPolicyAssessment = dmarcAssess,
            HasMtaSts = hasMtaSts,
            HasBimi = hasBimi,
            FoundDkimSelectors = foundDkimSelectors,
            EmailSecurityScore = score,
            EmailGrade = grade,
            Recommendations = recs,
            Summary = $"Email Security Grade {grade} ({score}/100) · Provider: {provider} · SPF: {(hasSpf ? "OK" : "MISSING")} · DMARC: {(hasDmarc ? "OK" : "MISSING")} · DKIM Selectors: {foundDkimSelectors.Count}."
        };
    }

    // -------------------------------------------------------------------------
    //  5. Hosting IP Deep Intel, 5 Live DNSBL Blacklists & 11-Port Probe
    // -------------------------------------------------------------------------

    private async Task<IpAndHostingIntel> AuditIpAndHostingAsync(string ipAddress, bool probePorts, CancellationToken ct)
    {
        string ptr = "(No PTR)";
        try
        {
            var hostEntry = await Dns.GetHostEntryAsync(ipAddress).ConfigureAwait(false);
            if (!string.IsNullOrWhiteSpace(hostEntry.HostName) && hostEntry.HostName != ipAddress)
                ptr = hostEntry.HostName;
        }
        catch { }

        // GeoIP / ASN / Hosting Org via ipwho.is (free HTTPS JSON, zero API key)
        string country = "Unknown", city = "", asn = "Unknown", org = "Unknown", isp = "Unknown";
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(7));
            var json = await _http.GetStringAsync($"https://ipwho.is/{Uri.EscapeDataString(ipAddress)}", cts.Token).ConfigureAwait(false);
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            if (root.TryGetProperty("success", out var ok) && ok.ValueKind == JsonValueKind.True)
            {
                country = root.TryGetProperty("country", out var c) ? c.GetString() ?? "Unknown" : "Unknown";
                city = root.TryGetProperty("city", out var ci) ? ci.GetString() ?? "" : "";
                if (root.TryGetProperty("connection", out var conn))
                {
                    if (conn.TryGetProperty("asn", out var a)) asn = $"AS{a}";
                    org = conn.TryGetProperty("org", out var o) ? o.GetString() ?? "Unknown" : "Unknown";
                    isp = conn.TryGetProperty("isp", out var i) ? i.GetString() ?? "Unknown" : "Unknown";
                }
            }
        }
        catch { }

        // Live DNSBL Blacklist checks (IPv4 reversed octets)
        var dnsblResults = new List<DnsblCheckResult>();
        if (IPAddress.TryParse(ipAddress, out var parsedIp) && parsedIp.AddressFamily == AddressFamily.InterNetwork)
        {
            var reversed = string.Join(".", ipAddress.Split('.').Reverse());
            var blTasks = DnsblZones.Select(async zone =>
            {
                var (recs, _) = await QueryDohRecordsAsync("https://cloudflare-dns.com/dns-query", $"{reversed}.{zone}", "A", ct).ConfigureAwait(false);
                var hit = recs.FirstOrDefault(r => r.Data.StartsWith("127.", StringComparison.Ordinal));
                return new DnsblCheckResult
                {
                    BlacklistZone = zone,
                    IsListed = hit is not null,
                    ResponseCode = hit is not null ? $"Listed ({hit.Data})" : "Clean"
                };
            });
            dnsblResults = (await Task.WhenAll(blTasks).ConfigureAwait(false)).ToList();
        }

        // Cross-check against synced abuse.ch Feodo C2 / URLhaus feeds
        var feedHit = _feeds.CheckIp(ipAddress);

        // Hosting TCP Port Probe
        var portProbes = new List<HostingPortProbeResult>();
        if (probePorts)
        {
            var pTasks = HostingPorts.Select(p => ProbePortAsync(ipAddress, p.Port, p.Name, p.HighRiskNote, ct));
            portProbes = (await Task.WhenAll(pTasks).ConfigureAwait(false)).ToList();
        }

        int blHits = dnsblResults.Count(d => d.IsListed);
        int openPorts = portProbes.Count(p => p.IsOpen);

        return new IpAndHostingIntel
        {
            IpAddress = ipAddress,
            ReversePtr = ptr,
            Country = country,
            City = city,
            Asn = asn,
            Organization = org,
            Isp = isp,
            IsThreatFeedHit = feedHit is not null,
            AbuseThreatFeedMatch = feedHit is not null
                ? $"CRITICAL MATCH: {feedHit.FeedSource} ({feedHit.Mitre.TechniqueId})"
                : "Clean (0 matches in abuse.ch Feodo/URLhaus)",
            BlacklistHitCount = blHits,
            DnsblResults = dnsblResults,
            PortProbes = portProbes,
            Summary = $"{ipAddress} ({org}, {asn}, {country}) · PTR: {ptr} · {blHits}/{dnsblResults.Count} DNSBL hits · {openPorts} open hosting port(s)."
        };
    }

    private static async Task<HostingPortProbeResult> ProbePortAsync(string ip, int port, string service, string note, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            using var tcp = new TcpClient();
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromMilliseconds(1500));
            await tcp.ConnectAsync(ip, port, cts.Token).ConfigureAwait(false);
            sw.Stop();
            return new HostingPortProbeResult { Port = port, ServiceName = service, IsOpen = true, LatencyMs = sw.ElapsedMilliseconds, ExposureNote = note };
        }
        catch
        {
            sw.Stop();
            return new HostingPortProbeResult { Port = port, ServiceName = service, IsOpen = false, LatencyMs = sw.ElapsedMilliseconds };
        }
    }

    // -------------------------------------------------------------------------
    //  6. Subdomain Discovery via Certificate Transparency (crt.sh)
    // -------------------------------------------------------------------------

    private async Task<List<DiscoveredSubdomainItem>> QueryCrtShSubdomainsAsync(string domain, CancellationToken ct)
    {
        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, $"https://crt.sh/?q=%25.{Uri.EscapeDataString(domain)}&output=json");
            req.Headers.UserAgent.ParseAdd("BECETTI-SECURITY/1.0");
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(10));
            using var resp = await _http.SendAsync(req, cts.Token).ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode) return new List<DiscoveredSubdomainItem>();

            var json = await resp.Content.ReadAsStringAsync(cts.Token).ConfigureAwait(false);
            return ParseCrtShJson(json, domain);
        }
        catch { return new List<DiscoveredSubdomainItem>(); }
    }

    internal static List<DiscoveredSubdomainItem> ParseCrtShJson(string json, string rootDomain)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var list = new List<DiscoveredSubdomainItem>();
        try
        {
            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.ValueKind != JsonValueKind.Array) return list;
            foreach (var el in doc.RootElement.EnumerateArray())
            {
                var nameVal = el.TryGetProperty("name_value", out var nv) ? nv.GetString() ?? "" : "";
                var issuer = el.TryGetProperty("issuer_name", out var iss) ? iss.GetString() ?? "" : "";
                var notAfter = el.TryGetProperty("not_after", out var na) ? na.GetString() ?? "" : "";

                foreach (var sub in nameVal.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
                {
                    var clean = sub.Trim().TrimStart('*', '.').ToLowerInvariant();
                    if (string.IsNullOrWhiteSpace(clean) || !clean.EndsWith(rootDomain, StringComparison.OrdinalIgnoreCase)) continue;
                    if (!seen.Add(clean)) continue;

                    list.Add(new DiscoveredSubdomainItem
                    {
                        Subdomain = clean,
                        IssuerName = ExtractCnShort(issuer),
                        NotAfter = notAfter.Length >= 10 ? notAfter[..10] : notAfter
                    });
                    if (list.Count >= 100) return list;
                }
            }
        }
        catch { }
        return list.OrderBy(s => s.Subdomain, StringComparer.OrdinalIgnoreCase).ToList();
    }

    // -------------------------------------------------------------------------
    //  HTML & JSON Export + Helpers
    // -------------------------------------------------------------------------

    public async Task<OperationResult<string>> ExportHtmlReportAsync(CompleteDomainHostingReport report, string outputPath, CancellationToken ct = default)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(outputPath)!);
            var sb = new StringBuilder();
            sb.AppendLine("<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"/>");
            sb.AppendLine($"<title>BECETTI SECURITY — Domain &amp; Hosting Audit: {WebUtility.HtmlEncode(report.NormalizedTarget)}</title>");
            sb.AppendLine("<style>body{font-family:Segoe UI,sans-serif;background:#090e1a;color:#f1f5f9;padding:32px;max-width:1080px;margin:auto}h1,h2{color:#38bdf8}.card{background:#111827;border:1px solid #1f2937;border-radius:12px;padding:18px;margin:14px 0}pre{white-space:pre-wrap;font-size:12px;color:#cbd5e1}</style></head><body>");
            sb.AppendLine($"<h1>BECETTI SECURITY — Domain, Hosting, DNS &amp; IP Audit</h1>");
            sb.AppendLine($"<p><strong>Target:</strong> {WebUtility.HtmlEncode(report.NormalizedTarget)} · <strong>Grade:</strong> {WebUtility.HtmlEncode(report.OverallGrade)} ({report.OverallScore}/100) · <strong>Audited:</strong> {report.AuditedAt.ToLocalTime():f}</p>");
            sb.AppendLine($"<div class=\"card\"><h2>Summary</h2><p>{WebUtility.HtmlEncode(report.Summary)}</p><p>{WebUtility.HtmlEncode(report.Rdap.Summary)}</p><p>{WebUtility.HtmlEncode(report.SslHosting.Summary)}</p><p>{WebUtility.HtmlEncode(report.EmailSecurity.Summary)}</p><p>{WebUtility.HtmlEncode(report.IpHosting.Summary)}</p></div>");
            sb.AppendLine($"<div class=\"card\"><h2>DNS Records ({report.DnsRecords.Count})</h2><pre>{WebUtility.HtmlEncode(string.Join("\n", report.DnsRecords.Select(r => r.DisplayLine)))}</pre></div>");
            sb.AppendLine($"<div class=\"card\"><h2>SSL &amp; Security Headers</h2><pre>{WebUtility.HtmlEncode(string.Join("\n", report.SslHosting.HeaderChecks.Select(h => h.DisplayLine)))}</pre></div>");
            sb.AppendLine($"<div class=\"card\"><h2>DNSBL &amp; Open Hosting Ports</h2><pre>{WebUtility.HtmlEncode(string.Join("\n", report.IpHosting.DnsblResults.Select(d => d.DisplayLine).Concat(report.IpHosting.PortProbes.Where(p => p.IsOpen).Select(p => p.DisplayLine))))}</pre></div>");
            sb.AppendLine("</body></html>");
            await File.WriteAllTextAsync(outputPath, sb.ToString(), Encoding.UTF8, ct).ConfigureAwait(false);
            return OperationResult<string>.Ok(outputPath, $"Exported Domain & Hosting HTML Report: {outputPath}");
        }
        catch (Exception ex)
        {
            return OperationResult<string>.Fail($"Failed to export HTML report: {ex.Message}");
        }
    }

    public async Task<OperationResult<string>> ExportJsonReportAsync(CompleteDomainHostingReport report, string outputPath, CancellationToken ct = default)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(outputPath)!);
            var json = JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true });
            await File.WriteAllTextAsync(outputPath, json, Encoding.UTF8, ct).ConfigureAwait(false);
            return OperationResult<string>.Ok(outputPath, $"Exported Domain & Hosting JSON Report: {outputPath}");
        }
        catch (Exception ex)
        {
            return OperationResult<string>.Fail($"Failed to export JSON report: {ex.Message}");
        }
    }

    internal static (string Normalized, bool IsIp, string Error) NormalizeTarget(string input)
    {
        if (string.IsNullOrWhiteSpace(input))
            return (string.Empty, false, "Enter a domain name (e.g. example.com), website URL, or IP address.");

        var trimmed = input.Trim();
        if (IPAddress.TryParse(trimmed, out _))
            return (trimmed, true, string.Empty);

        if (trimmed.Contains("://"))
        {
            if (Uri.TryCreate(trimmed, UriKind.Absolute, out var uri) && !string.IsNullOrWhiteSpace(uri.Host))
                trimmed = uri.Host;
        }
        else if (trimmed.Contains('/'))
        {
            trimmed = trimmed.Split('/')[0];
        }

        trimmed = trimmed.TrimEnd('.').ToLowerInvariant();
        if (IPAddress.TryParse(trimmed, out _))
            return (trimmed, true, string.Empty);

        if (!Regex.IsMatch(trimmed, @"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$"))
            return (string.Empty, false, $"'{input}' is not a valid domain name or IP address.");

        return (trimmed, false, string.Empty);
    }

    private static int ComputeOverallDomainScore(SslAndHostingAudit ssl, EmailDomainSecurityAudit email, IpAndHostingIntel ip, bool dnssec)
    {
        int score = (int)Math.Round((ssl.HostingSecurityScore * 0.45) + (email.EmailSecurityScore * 0.35) + (dnssec ? 10 : 0) + (ip.BlacklistHitCount == 0 && !ip.IsThreatFeedHit ? 10 : 0));
        if (ip.IsThreatFeedHit) score = Math.Min(score, 25);
        return Math.Clamp(score, 0, 100);
    }

    private static string ScoreToGrade(int score) => score switch
    {
        >= 92 => "A+",
        >= 84 => "A",
        >= 74 => "B",
        >= 60 => "C",
        >= 45 => "D",
        _ => "F"
    };

    private static string ExtractCnShort(string? dn)
    {
        var safe = dn ?? string.Empty;
        foreach (var p in safe.Split(','))
        {
            var t = p.Trim();
            if (t.StartsWith("CN=", StringComparison.OrdinalIgnoreCase)) return t[3..].Trim();
            if (t.StartsWith("O=", StringComparison.OrdinalIgnoreCase)) return t[2..].Trim();
        }
        return safe.Length > 36 ? safe[..36] + "…" : safe;
    }
}
