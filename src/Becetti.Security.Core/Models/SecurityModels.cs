using System.Text.Json.Serialization;

namespace Becetti.Security.Core.Models;

/// <summary>Type of scan requested through Microsoft Defender (MpCmdRun / Start-MpScan).</summary>
public enum DefenderScanType
{
    Quick = 1,
    Full = 2,
    Custom = 3
}

/// <summary>Verified Microsoft Defender / Windows Security state (from Get-MpComputerStatus).</summary>
public sealed class DefenderStatus
{
    /// <summary>True when the Defender service answered. False means the status is unknown, not "safe".</summary>
    public bool Available { get; init; }
    public bool AntivirusEnabled { get; init; }
    public bool RealTimeProtectionEnabled { get; init; }
    public bool BehaviorMonitorEnabled { get; init; }
    public bool IoavProtectionEnabled { get; init; }
    public bool NetworkProtectionEnabled { get; init; }
    public bool TamperProtectionEnabled { get; init; }
    /// <summary>
    /// Cloud-delivered protection (MAPS) level from Get-MpPreference's MAPSReporting:
    /// "Disabled", "Basic", "Advanced", or "Unknown" when Get-MpPreference could not be read.
    /// </summary>
    public string CloudProtectionLevel { get; init; } = "Unknown";
    /// <summary>
    /// Automatic sample submission mode from Get-MpPreference's SubmitSamplesConsent:
    /// "Always Prompt", "Send Safe Samples", "Never Send", "Send All Samples", or "Unknown".
    /// </summary>
    public string SampleSubmissionMode { get; init; } = "Unknown";
    public string? AntivirusSignatureVersion { get; init; }
    public DateTimeOffset? AntivirusSignatureLastUpdated { get; init; }
    public DateTimeOffset? QuickScanEndTime { get; init; }
    public DateTimeOffset? FullScanEndTime { get; init; }
    /// <summary>
    /// Raw AMRunningMode from Get-MpComputerStatus (e.g. "Normal", "Passive Mode",
    /// "SxS Passive Mode", "EDR Block Mode"). Anything other than "Normal" means a
    /// third-party antivirus is the active real-time engine and Defender is running
    /// alongside it in a reduced role.
    /// </summary>
    public string? RunningMode { get; init; }
    /// <summary>True when RunningMode indicates another antivirus product is managing real-time protection.</summary>
    public bool ManagedByAnotherAntivirus =>
        !string.IsNullOrWhiteSpace(RunningMode) &&
        !string.Equals(RunningMode, "Normal", StringComparison.OrdinalIgnoreCase);
    public string? RawError { get; init; }
}

/// <summary>A single firewall profile state (from Get-NetFirewallProfile).</summary>
public sealed class FirewallProfileStatus
{
    public string Name { get; init; } = string.Empty;
    public bool Enabled { get; init; }
}

/// <summary>
/// Real ransomware (Controlled Folder Access) state, read only from
/// Get-MpPreference. BECETTI SECURITY never implements its own ransomware
/// detection — it only surfaces and explains Defender's own Exploit Guard
/// feature and lets the user change it through the same, real Set-MpPreference
/// interface Windows Security itself uses.
/// </summary>
public sealed class RansomwareProtectionStatus
{
    /// <summary>True once Get-MpPreference answered at all.</summary>
    public bool Available { get; init; }

    /// <summary>
    /// Raw EnableControlledFolderAccess value from Get-MpPreference:
    /// 0 = Disabled, 1 = Enabled (block), 2 = Audit Mode, 3 = Block disk modification only,
    /// 4 = Audit disk modification only. -1 means it could not be read.
    /// </summary>
    public int ControlledFolderAccessRaw { get; init; } = -1;

    public bool ControlledFolderAccessEnabled => ControlledFolderAccessRaw is 1 or 2 or 3 or 4;

    /// <summary>Human-readable form of <see cref="ControlledFolderAccessRaw"/>, never guessed.</summary>
    public string ControlledFolderAccessState => ControlledFolderAccessRaw switch
    {
        0 => "Disabled",
        1 => "Enabled (Block)",
        2 => "Audit Mode",
        3 => "Block Disk Modification Only",
        4 => "Audit Disk Modification Only",
        _ => "Unknown"
    };

    /// <summary>Folders Defender is actively protecting from unauthorized changes. Empty if none or unreadable.</summary>
    public IReadOnlyList<string> ProtectedFolders { get; init; } = Array.Empty<string>();

    /// <summary>Apps the user has explicitly allowed to modify protected folders.</summary>
    public IReadOnlyList<string> AllowedApplications { get; init; } = Array.Empty<string>();

    public string? RawError { get; init; }
}

/// <summary>A threat detection reported by Microsoft Defender (from Get-MpThreatDetection).</summary>
public sealed class ThreatInfo
{
    public string ThreatId { get; init; } = string.Empty;
    public string ThreatName { get; init; } = string.Empty;
    public string Severity { get; init; } = "Unknown";
    public string Category { get; init; } = "Unknown";
    public string Resources { get; init; } = string.Empty;
    public DateTimeOffset? DetectedAt { get; init; }
    public bool ActionSucceeded { get; init; }
    public string? ActionTaken { get; init; }
}

/// <summary>Outcome of a Defender scan run.</summary>
public sealed class ScanOutcome
{
    public DefenderScanType ScanType { get; init; }
    public string? TargetPath { get; init; }
    public DateTimeOffset StartedAt { get; init; }
    public DateTimeOffset EndedAt { get; init; }
    public int ProcessExitCode { get; init; }
    /// <summary>True only when MpCmdRun exited 0 (scan completed, no threat found).</summary>
    public bool CompletedWithoutThreat { get; init; }
    /// <summary>True when MpCmdRun exited 2 (threat found). The app never declares this itself.</summary>
    public bool ThreatFound { get; init; }
    public string Output { get; init; } = string.Empty;
    public string? Error { get; init; }
}

/// <summary>Verified device / system information.</summary>
public sealed class DeviceInfo
{
    public string DeviceName { get; init; } = string.Empty;
    public string OsDescription { get; init; } = string.Empty;
    public string OsBuild { get; init; } = string.Empty;
    public string Architecture { get; init; } = string.Empty;
    public string RuntimeVersion { get; init; } = string.Empty;
    public bool DefenderInstalled { get; init; }
    public string? DefenderPath { get; init; }
    public bool IsAdministrator { get; init; }
    public bool UacEnabled { get; init; }
    public long SystemDriveFreeBytes { get; init; }
    public long SystemDriveTotalBytes { get; init; }
}

/// <summary>Network / privacy check result. Every field is measured, never assumed.</summary>
public sealed class NetworkCheckResult
{
    public bool NetworkAvailable { get; init; }
    public string? ActiveAdapter { get; init; }
    public bool DnsResolvable { get; init; }
    public bool TlsHandshakeOk { get; init; }
    public string? TlsDetail { get; init; }
    public DateTimeOffset CheckedAt { get; init; }
}

/// <summary>One entry in the local security event history (only real events are recorded).</summary>
public sealed class SecurityEvent
{
    [JsonPropertyName("timestamp")]
    public DateTimeOffset Timestamp { get; set; } = DateTimeOffset.UtcNow;

    [JsonPropertyName("type")]
    public string Type { get; set; } = string.Empty;

    [JsonPropertyName("summary")]
    public string Summary { get; set; } = string.Empty;

    [JsonPropertyName("detail")]
    public string? Detail { get; set; }

    [JsonPropertyName("success")]
    public bool Success { get; set; }
}

/// <summary>Cloud API health response.</summary>
public sealed class CloudHealth
{
    public string Status { get; init; } = string.Empty;
    public string Version { get; init; } = string.Empty;
    public DateTimeOffset ServerTime { get; init; }
}

/// <summary>Authenticated cloud session tokens.</summary>
public sealed class AuthTokens
{
    public string AccessToken { get; init; } = string.Empty;
    public string RefreshToken { get; init; } = string.Empty;
    public DateTimeOffset ExpiresAt { get; init; }
}

/// <summary>File reputation verdict returned by the cloud API (real server response only).</summary>
public sealed class ReputationVerdict
{
    public string Sha256 { get; init; } = string.Empty;
    /// <summary>clean | malicious | suspicious | unknown</summary>
    public string Verdict { get; init; } = "unknown";
    public string Source { get; init; } = string.Empty;
    public string? Detail { get; init; }
    public DateTimeOffset CheckedAt { get; init; }
}

/// <summary>
/// One contributing factor behind a <see cref="SecurityScoreResult"/>: a real,
/// named signal (e.g. "Real-time protection is off") plus the points it added
/// or removed. Never decorative text with no real signal behind it.
/// </summary>
public sealed class SecurityScoreFactor
{
    public string Title { get; init; } = string.Empty;
    public string Detail { get; init; } = string.Empty;
    /// <summary>Positive to add to the score, negative to subtract. Never zero (would not be listed).</summary>
    public int PointsDelta { get; init; }
    public bool IsPositive => PointsDelta >= 0;
}

/// <summary>
/// 0-100 security score computed only from real, already-verified signals
/// (Defender, firewall, Controlled Folder Access, signature freshness). The
/// score and every factor behind it are recomputed fresh each time from
/// whatever was actually read moments earlier — nothing here is cached,
/// randomized, or a fixed placeholder number.
/// </summary>
public sealed class SecurityScoreResult
{
    /// <summary>0-100. Null only when nothing at all could be verified (e.g. Defender totally unreachable).</summary>
    public int? Score { get; init; }

    public string Grade => Score switch
    {
        null => "Unknown",
        >= 90 => "Excellent",
        >= 75 => "Good",
        >= 50 => "Needs Attention",
        _ => "At Risk"
    };

    public IReadOnlyList<SecurityScoreFactor> Factors { get; init; } = Array.Empty<SecurityScoreFactor>();
}

/// <summary>Real-time CPU/RAM snapshot from GetSystemTimes/GlobalMemoryStatusEx (Windows only).</summary>
public sealed class PerformanceSnapshot
{
    public bool Available { get; init; }
    public double CpuUsagePercent { get; init; }
    public ulong TotalPhysicalMemoryBytes { get; init; }
    public ulong AvailablePhysicalMemoryBytes { get; init; }
    public double MemoryLoadPercent { get; init; }
}

/// <summary>Real free/total space for one fixed local drive (from DriveInfo).</summary>
public sealed class DiskHealthInfo
{
    public string Name { get; init; } = string.Empty;
    public string VolumeLabel { get; init; } = string.Empty;
    public long FreeBytes { get; init; }
    public long TotalBytes { get; init; }
    public double FreePercent => TotalBytes <= 0 ? 0 : Math.Round(FreeBytes * 100.0 / TotalBytes, 1);
    public bool IsLowSpace => TotalBytes > 0 && FreePercent < 10.0;
    public bool HasEnoughSpace => !IsLowSpace;
    public string DisplayName => string.IsNullOrWhiteSpace(VolumeLabel) ? Name : $"{Name} {VolumeLabel}";
}

/// <summary>Real running/stopped state of one essential Windows service (from ServiceController).</summary>
public sealed class ServiceHealthInfo
{
    public string ServiceName { get; init; } = string.Empty;
    public string DisplayName { get; init; } = string.Empty;
    public string Status { get; init; } = "Unknown";
    public bool IsRunning { get; init; }
    /// <summary>True for services BECETTI SECURITY explains as security/update-relevant (Defender, Firewall, Update, BITS, Task Scheduler).</summary>
    public bool IsSecurityRelevant { get; init; }
}

/// <summary>Full PC health snapshot: performance + disks + essential services, all read live.</summary>
public sealed class PcHealthSnapshot
{
    public PerformanceSnapshot Performance { get; init; } = new();
    public IReadOnlyList<DiskHealthInfo> Disks { get; init; } = Array.Empty<DiskHealthInfo>();
    public IReadOnlyList<ServiceHealthInfo> Services { get; init; } = Array.Empty<ServiceHealthInfo>();
    public DateTimeOffset CheckedAt { get; init; } = DateTimeOffset.Now;
}

/// <summary>Application update check result from the cloud API.</summary>
public sealed class UpdateCheckResult
{
    public string CurrentVersion { get; init; } = string.Empty;
    public string? LatestVersion { get; init; }
    public bool UpdateAvailable { get; init; }
    public string Channel { get; init; } = "stable";
    public string? ReleaseNotes { get; init; }
    public string? StoreUrl { get; init; }
}
