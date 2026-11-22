using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

/// <summary>
/// Client for BECETTI SECURITY's VirusTotal proxy (see /backend/becetti-ai).
/// This class never talks to VirusTotal directly and never contains a key —
/// only the backend's own public URL, which is itself just a relay. Every
/// call is a real HTTP request; on any failure this returns a real error —
/// it never fabricates a detection result.
///
/// VirusTotal is an optional second opinion from ~70 third-party engines.
/// BECETTI SECURITY's own protection engine stays Microsoft Defender,
/// independent of this integration.
/// </summary>
public interface IThreatIntelligenceService
{
    bool IsConfigured { get; }

    /// <summary>Maximum raw file size this integration will upload for a fresh scan (matches the server-side cap).</summary>
    long MaxUploadBytes { get; }

    /// <summary>
    /// Looks up an already-computed SHA-256 against VirusTotal's database.
    /// Never uploads file content — only the hash is sent.
    /// </summary>
    Task<OperationResult<ThreatIntelReport>> CheckFileHashAsync(string sha256, string? fileName, CancellationToken ct = default);

    /// <summary>
    /// Hashes the file locally, checks the hash first, and — only when the
    /// caller has explicitly confirmed upload consent (<paramref name="allowUpload"/>)
    /// and VirusTotal has no existing report — uploads the file content for a fresh scan.
    /// </summary>
    Task<OperationResult<ThreatIntelReport>> ScanFileAsync(string filePath, bool allowUpload, CancellationToken ct = default);

    /// <summary>Submits a URL to VirusTotal for analysis.</summary>
    Task<OperationResult<ThreatIntelReport>> SubmitUrlAsync(string url, CancellationToken ct = default);

    /// <summary>Polls a previously submitted analysis id for its real, current status.</summary>
    Task<OperationResult<ThreatIntelReport>> GetAnalysisAsync(string analysisId, ThreatIntelTargetType targetType, CancellationToken ct = default);
}
