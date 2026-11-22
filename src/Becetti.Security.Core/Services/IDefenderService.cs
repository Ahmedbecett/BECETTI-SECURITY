using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

/// <summary>
/// Genuine Microsoft Defender integration. Every method talks to a real
/// Windows security interface (Get-MpComputerStatus / Get-MpThreatDetection /
/// MpCmdRun.exe / Set-MpPreference / Update-MpSignature). Nothing here is
/// simulated: if Defender is missing or the call fails, the failure is returned.
/// </summary>
public interface IDefenderService
{
    /// <summary>Locate MpCmdRun.exe. Null when Defender is not installed.</summary>
    string? FindMpCmdRun();

    /// <summary>True when the current process runs elevated (administrator).</summary>
    bool IsElevated();

    /// <summary>Restart the current executable elevated via UAC (Windows only).</summary>
    OperationResult RestartElevated();

    /// <summary>Read verified Defender status via Get-MpComputerStatus.</summary>
    Task<OperationResult<DefenderStatus>> GetStatusAsync(CancellationToken ct = default);

    /// <summary>Read firewall profile states via Get-NetFirewallProfile.</summary>
    Task<OperationResult<IReadOnlyList<FirewallProfileStatus>>> GetFirewallAsync(CancellationToken ct = default);

    /// <summary>
    /// Read real Controlled Folder Access (ransomware protection) state via
    /// Get-MpPreference. This is Microsoft Defender's own Exploit Guard
    /// feature — BECETTI SECURITY only reads and explains it, it never
    /// implements its own ransomware detection engine.
    /// </summary>
    Task<OperationResult<RansomwareProtectionStatus>> GetRansomwareProtectionAsync(CancellationToken ct = default);

    /// <summary>
    /// Enable/disable Controlled Folder Access via Set-MpPreference
    /// (requires elevation). Verified by re-reading Get-MpPreference before
    /// reporting success.
    /// </summary>
    Task<OperationResult> SetControlledFolderAccessAsync(bool enable, CancellationToken ct = default);

    /// <summary>Read real threat detections via Get-MpThreatDetection.</summary>
    Task<OperationResult<IReadOnlyList<ThreatInfo>>> GetThreatsAsync(CancellationToken ct = default);

    /// <summary>
    /// Run a real Defender scan via MpCmdRun.exe. For Custom scans,
    /// <paramref name="targetPath"/> must be an existing file or folder.
    /// </summary>
    Task<OperationResult<ScanOutcome>> RunScanAsync(DefenderScanType scanType, string? targetPath = null, CancellationToken ct = default);

    /// <summary>
    /// Update Defender security intelligence via Update-MpSignature
    /// -UpdateSource MicrosoftUpdateServer, falling back to MpCmdRun.exe
    /// -SignatureUpdate (requires elevation). Only Microsoft's own update
    /// service is ever contacted; the result is verified by re-reading
    /// Get-MpComputerStatus before reporting success.
    /// </summary>
    Task<OperationResult> UpdateSignaturesAsync(CancellationToken ct = default);

    /// <summary>Enable/disable real-time monitoring via Set-MpPreference (requires elevation).</summary>
    Task<OperationResult> SetRealTimeProtectionAsync(bool enable, CancellationToken ct = default);

    /// <summary>Remove a threat via Remove-MpThreat (requires elevation). Verified by re-query.</summary>
    Task<OperationResult> RemoveThreatAsync(string threatId, CancellationToken ct = default);
}
