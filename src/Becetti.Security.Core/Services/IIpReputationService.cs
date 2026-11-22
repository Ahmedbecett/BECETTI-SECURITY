using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

/// <summary>
/// Client for BECETTI SECURITY's AbuseIPDB proxy (see /backend/becetti-ai).
/// This class never talks to AbuseIPDB directly and never contains a key —
/// only the backend's own public URL, which also serves BECETTI AI and the
/// VirusTotal/data-breach proxies. Every call is a real HTTP request; on
/// any failure this returns a real error — it never fabricates a score.
/// </summary>
public interface IIpReputationService
{
    bool IsConfigured { get; }

    /// <summary>Checks a single IP address's real abuse-report history via AbuseIPDB.</summary>
    Task<OperationResult<IpReputationReport>> CheckIpAsync(string ipAddress, CancellationToken ct = default);
}
