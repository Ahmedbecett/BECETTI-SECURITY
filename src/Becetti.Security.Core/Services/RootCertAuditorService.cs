using System.Security.Cryptography.X509Certificates;
using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

public interface IRootCertAuditorService
{
    Task<OperationResult<RootCertAuditReport>> AuditRootCertificatesAsync(CancellationToken ct = default);
}

/// <summary>
/// #5: Windows Root Certificate Store Auditor.
/// Inspects real X509Store(StoreName.Root) across CurrentUser and LocalMachine to surface
/// user-installed root CAs (classic HTTPS MITM / adware interception vector), weak SHA-1/MD5
/// signature algorithms, and expired root certificates. Zero simulation.
/// </summary>
public sealed class RootCertAuditorService : IRootCertAuditorService
{
    private static readonly string[] KnownTrustedPublishers =
    {
        "Microsoft", "DigiCert", "GlobalSign", "Sectigo", "COMODO", "Entrust",
        "ISRG Root", "Let's Encrypt", "Google Trust Services", "Amazon Root",
        "Baltimore", "GeoTrust", "Thawte", "VeriSign", "Go Daddy", "Starfield",
        "USERTrust", "QuoVadis", "SwissSign", "Certum", "Actalis", "IdenTrust",
        "AAA Certificate", "AffirmTrust", "Buypass", "D-TRUST", "SSL.com", "HARICA"
    };

    public async Task<OperationResult<RootCertAuditReport>> AuditRootCertificatesAsync(CancellationToken ct = default)
    {
        var items = new List<RootCertificateAuditItem>();

        await Task.Run(() =>
        {
            InspectStore(StoreLocation.CurrentUser, "CurrentUser", items, ct);
            InspectStore(StoreLocation.LocalMachine, "LocalMachine", items, ct);
        }, ct).ConfigureAwait(false);

        var deduped = items
            .GroupBy(i => $"{i.StoreScope}|{i.Thumbprint}", StringComparer.OrdinalIgnoreCase)
            .Select(g => g.First())
            .OrderByDescending(i => i.RiskLevel == "Critical")
            .ThenByDescending(i => i.RiskLevel == "High")
            .ThenByDescending(i => i.RiskLevel == "Medium")
            .ThenBy(i => i.Subject, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var flagged = deduped.Count(i => i.RiskLevel != "Normal");
        var summary = flagged > 0
            ? $"Root CA Audit: {flagged} flagged certificate(s) out of {deduped.Count} total trusted Root CAs."
            : $"Root CA Audit Clean: {deduped.Count} Root CAs inspected, 0 suspicious or weak certificates.";

        return OperationResult<RootCertAuditReport>.Ok(new RootCertAuditReport
        {
            AuditedAt = DateTimeOffset.UtcNow,
            TotalRootCerts = deduped.Count,
            FlaggedCerts = flagged,
            Items = deduped,
            Summary = summary
        }, summary);
    }

    private static void InspectStore(StoreLocation location, string scopeName, List<RootCertificateAuditItem> target, CancellationToken ct)
    {
        try
        {
            using var store = new X509Store(StoreName.Root, location);
            store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
            var now = DateTimeOffset.UtcNow;

            foreach (var cert in store.Certificates)
            {
                if (ct.IsCancellationRequested) break;
                try
                {
                    var subj = cert.Subject ?? string.Empty;
                    var issuer = cert.Issuer ?? string.Empty;
                    var alg = cert.SignatureAlgorithm?.FriendlyName ?? cert.SignatureAlgorithm?.Value ?? "Unknown";
                    var notAfter = new DateTimeOffset(cert.NotAfter.ToUniversalTime());
                    var notBefore = new DateTimeOffset(cert.NotBefore.ToUniversalTime());

                    bool expired = notAfter < now;
                    bool weakAlg = alg.Contains("md5", StringComparison.OrdinalIgnoreCase) ||
                                   alg.Contains("md2", StringComparison.OrdinalIgnoreCase) ||
                                   alg.Contains("sha1", StringComparison.OrdinalIgnoreCase);
                    bool userInstalled = location == StoreLocation.CurrentUser;
                    bool knownPub = KnownTrustedPublishers.Any(k => subj.Contains(k, StringComparison.OrdinalIgnoreCase));

                    var reasons = new List<string>();
                    string risk = "Normal";

                    if (userInstalled && !knownPub)
                    {
                        risk = "High";
                        reasons.Add("Non-standard Root CA installed in CurrentUser store (potential HTTPS MITM proxy)");
                    }
                    if (weakAlg && !knownPub)
                    {
                        risk = risk == "High" ? "Critical" : "Medium";
                        reasons.Add($"Weak signature algorithm ({alg})");
                    }
                    if (expired)
                    {
                        if (risk == "Normal") risk = "Low";
                        reasons.Add("Expired root certificate");
                    }

                    target.Add(new RootCertificateAuditItem
                    {
                        StoreScope = scopeName,
                        Subject = TrimCn(subj),
                        Issuer = TrimCn(issuer),
                        Thumbprint = cert.Thumbprint ?? string.Empty,
                        SignatureAlgorithm = alg,
                        NotBefore = notBefore,
                        NotAfter = notAfter,
                        IsExpired = expired,
                        IsWeakAlgorithm = weakAlg,
                        IsUserInstalled = userInstalled,
                        RiskLevel = risk,
                        RiskReason = string.Join("; ", reasons)
                    });
                }
                finally
                {
                    cert.Dispose();
                }
            }
        }
        catch { }
    }

    private static string TrimCn(string dn)
    {
        foreach (var part in (dn ?? string.Empty).Split(','))
        {
            var t = part.Trim();
            if (t.StartsWith("CN=", StringComparison.OrdinalIgnoreCase))
                return t[3..].Trim();
        }
        return dn.Length > 72 ? dn[..72] + "…" : dn;
    }
}
