namespace Becetti.Security.Core.Models;

// =========================================================================
//  Global Domain, Hosting, DNS & IP Security Intelligence Suite Models
// =========================================================================

public sealed class DnsRecordItem
{
    public string RecordType { get; init; } = string.Empty; // A, AAAA, MX, NS, TXT, CNAME, SOA, CAA, DS
    public string Name { get; init; } = string.Empty;
    public int Ttl { get; init; }
    public string Data { get; init; } = string.Empty;

    public string DisplayLine => $"[{RecordType,-5}] TTL {Ttl,-6} · {Data}";
}

public sealed class DnsPropagationCheck
{
    public string ResolverName { get; init; } = string.Empty;
    public string ResolverIp { get; init; } = string.Empty;
    public bool Succeeded { get; init; }
    public bool DnssecValidated { get; init; }
    public string ResolvedValues { get; init; } = string.Empty;
    public long LatencyMs { get; init; }

    public string DisplayLine =>
        $"{ResolverName,-16} ({ResolverIp,-15}) · {(Succeeded ? ResolvedValues : "No Answer / Failed")} · {LatencyMs} ms" +
        (DnssecValidated ? " [DNSSEC]" : "");
}

public sealed class DomainRdapInfo
{
    public bool Available { get; init; }
    public string DomainName { get; init; } = string.Empty;
    public string Registrar { get; init; } = "Unknown";
    public DateTimeOffset? CreatedDate { get; init; }
    public DateTimeOffset? UpdatedDate { get; init; }
    public DateTimeOffset? ExpirationDate { get; init; }
    public int? DaysUntilExpiry { get; init; }
    public IReadOnlyList<string> StatusFlags { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> NameServers { get; init; } = Array.Empty<string>();
    public string Summary { get; init; } = string.Empty;
}

public sealed class SecurityHeaderCheck
{
    public string HeaderName { get; init; } = string.Empty;
    public bool Present { get; init; }
    public string Value { get; init; } = string.Empty;
    public string Recommendation { get; init; } = string.Empty;

    public string DisplayLine =>
        (Present ? "[PASS] " : "[MISSING] ") + $"{HeaderName}: {(Present ? Value : Recommendation)}";
}

public sealed class SslAndHostingAudit
{
    public bool SslReachable { get; init; }
    public string TlsProtocol { get; init; } = "Unavailable";
    public string CertSubject { get; init; } = string.Empty;
    public string CertIssuer { get; init; } = string.Empty;
    public DateTimeOffset? ValidFrom { get; init; }
    public DateTimeOffset? ValidTo { get; init; }
    public int? DaysRemaining { get; init; }
    public string Thumbprint { get; init; } = string.Empty;
    public IReadOnlyList<string> SubjectAltNames { get; init; } = Array.Empty<string>();

    public bool HttpRedirectsToHttps { get; init; }
    public int HttpStatusCode { get; init; }
    public string ServerBanner { get; init; } = "Hidden";
    public string PoweredByBanner { get; init; } = "Hidden";
    public string DetectedCdnOrHost { get; init; } = "Direct / Unknown";
    public int HostingSecurityScore { get; init; }
    public string HostingGrade { get; init; } = "—";
    public IReadOnlyList<SecurityHeaderCheck> HeaderChecks { get; init; } = Array.Empty<SecurityHeaderCheck>();
    public string Summary { get; init; } = string.Empty;
}

public sealed class EmailDomainSecurityAudit
{
    public string Domain { get; init; } = string.Empty;
    public string MailProviderGuess { get; init; } = "Custom / Direct MX";
    public IReadOnlyList<string> MxRecords { get; init; } = Array.Empty<string>();
    public bool HasSpf { get; init; }
    public string SpfRecord { get; init; } = "(Not Found)";
    public string SpfPolicyAssessment { get; init; } = string.Empty;
    public bool HasDmarc { get; init; }
    public string DmarcRecord { get; init; } = "(Not Found)";
    public string DmarcPolicyAssessment { get; init; } = string.Empty;
    public bool HasMtaSts { get; init; }
    public bool HasBimi { get; init; }
    public IReadOnlyList<string> FoundDkimSelectors { get; init; } = Array.Empty<string>();
    public int EmailSecurityScore { get; init; }
    public string EmailGrade { get; init; } = "—";
    public IReadOnlyList<string> Recommendations { get; init; } = Array.Empty<string>();
    public string Summary { get; init; } = string.Empty;
}

public sealed class DnsblCheckResult
{
    public string BlacklistZone { get; init; } = string.Empty;
    public bool IsListed { get; init; }
    public string ResponseCode { get; init; } = "Clean";

    public string DisplayLine =>
        (IsListed ? "[LISTED] " : "[CLEAN]  ") + $"{BlacklistZone,-28} · {ResponseCode}";
}

public sealed class HostingPortProbeResult
{
    public int Port { get; init; }
    public string ServiceName { get; init; } = string.Empty;
    public bool IsOpen { get; init; }
    public long LatencyMs { get; init; }
    public string ExposureNote { get; init; } = string.Empty;

    public string DisplayLine =>
        (IsOpen ? "[OPEN]   " : "[CLOSED] ") + $"TCP/{Port,-5} ({ServiceName,-12}) · {LatencyMs} ms" +
        (string.IsNullOrWhiteSpace(ExposureNote) ? "" : $" · {ExposureNote}");
}

public sealed class IpAndHostingIntel
{
    public string IpAddress { get; init; } = string.Empty;
    public string ReversePtr { get; init; } = "(No PTR)";
    public string Country { get; init; } = "Unknown";
    public string City { get; init; } = string.Empty;
    public string Asn { get; init; } = "Unknown";
    public string Organization { get; init; } = "Unknown";
    public string Isp { get; init; } = "Unknown";
    public string AbuseThreatFeedMatch { get; init; } = "Clean (0 matches in abuse.ch feeds)";
    public bool IsThreatFeedHit { get; init; }
    public int BlacklistHitCount { get; init; }
    public IReadOnlyList<DnsblCheckResult> DnsblResults { get; init; } = Array.Empty<DnsblCheckResult>();
    public IReadOnlyList<HostingPortProbeResult> PortProbes { get; init; } = Array.Empty<HostingPortProbeResult>();
    public string Summary { get; init; } = string.Empty;
}

public sealed class DiscoveredSubdomainItem
{
    public string Subdomain { get; init; } = string.Empty;
    public string IssuerName { get; init; } = string.Empty;
    public string NotAfter { get; init; } = string.Empty;

    public string DisplayLine => $"{Subdomain,-42} · CA: {IssuerName} · Exp: {NotAfter}";
}

public sealed class CompleteDomainHostingReport
{
    public string QueryInput { get; init; } = string.Empty;
    public string NormalizedTarget { get; init; } = string.Empty;
    public bool IsIpOnlyQuery { get; init; }
    public DateTimeOffset AuditedAt { get; init; } = DateTimeOffset.UtcNow;

    public IReadOnlyList<DnsRecordItem> DnsRecords { get; init; } = Array.Empty<DnsRecordItem>();
    public IReadOnlyList<DnsPropagationCheck> PropagationChecks { get; init; } = Array.Empty<DnsPropagationCheck>();
    public bool DnssecEnabled { get; init; }

    public DomainRdapInfo Rdap { get; init; } = new();
    public SslAndHostingAudit SslHosting { get; init; } = new();
    public EmailDomainSecurityAudit EmailSecurity { get; init; } = new();
    public IpAndHostingIntel IpHosting { get; init; } = new();
    public IReadOnlyList<DiscoveredSubdomainItem> Subdomains { get; init; } = Array.Empty<DiscoveredSubdomainItem>();

    public int OverallScore { get; init; }
    public string OverallGrade { get; init; } = "—";
    public string Summary { get; init; } = string.Empty;
}
