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

/// <summary>
/// One real registry-based startup entry — the same Run-key + StartupApproved
/// model Windows Task Manager's own "Startup apps" tab reads and writes.
/// BECETTI SECURITY does not invent a "performance impact" score here: Windows
/// does not expose that through any stable public API outside Task Manager's
/// own ETW boot trace, so this only ever reports what can be verified (name,
/// command, location, and real enabled/disabled state).
/// </summary>
public sealed class StartupItemInfo
{
    public string Name { get; init; } = string.Empty;
    public string Command { get; init; } = string.Empty;
    /// <summary>Human-readable origin, e.g. "This user" or "All users".</summary>
    public string LocationDisplay { get; init; } = string.Empty;
    /// <summary>Internal routing key ("HKCU", "HKLM", "HKLM32") used only to resolve the registry path when toggling — not meant for display.</summary>
    public string LocationKey { get; init; } = string.Empty;
    public bool IsEnabled { get; init; }
    /// <summary>True for HKLM-based entries, which need an administrator to change.</summary>
    public bool RequiresElevationToChange { get; init; }
}

/// <summary>
/// One application from the real Windows "installed programs" registry
/// inventory (the same source Settings &gt; Apps reads). Uninstalling always
/// launches the program's own real uninstaller — BECETTI SECURITY never
/// removes files itself or bypasses that confirmation step.
/// </summary>
public sealed class InstalledAppInfo
{
    public string Name { get; init; } = string.Empty;
    public string? Version { get; init; }
    public string? Publisher { get; init; }
    public DateTimeOffset? InstallDate { get; init; }
    public string? UninstallCommand { get; init; }
    public bool CanUninstall => !string.IsNullOrWhiteSpace(UninstallCommand);
}

/// <summary>
/// One global Windows privacy permission switch (Camera, Microphone,
/// Location), read from the real CapabilityAccessManager ConsentStore
/// registry key that Settings &gt; Privacy &amp; security itself reads and
/// writes. This is the device-wide master switch, not a per-app grant list —
/// BECETTI SECURITY only reports what it can verify.
/// </summary>
public sealed class PrivacyPermissionInfo
{
    public string Name { get; init; } = string.Empty;
    /// <summary>true = allowed, false = blocked, null = could not be determined.</summary>
    public bool? Allowed { get; init; }
    public string StateText => Allowed switch
    {
        true => "Allowed",
        false => "Blocked",
        null => "Unknown"
    };
}

/// <summary>One installed device driver from WMI's real Win32_PnPSignedDriver class —
/// the same inventory Device Manager is built on. No "known issue" database
/// is attached: BECETTI SECURITY has none of its own, so it only ever points
/// the user to Windows Update / the manufacturer as the official source.
/// </summary>
public sealed class DriverInfo
{
    public string DeviceName { get; init; } = string.Empty;
    public string? DeviceClass { get; init; }
    public string? Manufacturer { get; init; }
    public string? DriverVersion { get; init; }
    public DateTimeOffset? DriverDate { get; init; }
    public bool IsSigned { get; init; }
}

/// <summary>
/// One removable (USB/flash/external) drive currently plugged in, read from
/// the real .NET <see cref="System.IO.DriveInfo"/> API (the same source
/// Windows Explorer itself uses) — never a simulated device list.
/// </summary>
public sealed class UsbDriveInfo
{
    /// <summary>Drive root, e.g. "E:\". Used as the scan target path.</summary>
    public string RootPath { get; init; } = string.Empty;
    public string? VolumeLabel { get; init; }
    public string? FileSystem { get; init; }
    public long? TotalSizeBytes { get; init; }
    public long? AvailableFreeBytes { get; init; }
    public bool IsReady { get; init; }
}

/// <summary>
/// Real Windows AutoPlay/AutoRun policy state, read from the same registry
/// values (HKLM Policies\Explorer\NoDriveTypeAutoRun and NoAutorun) Windows'
/// own Group Policy engine reads and writes. BECETTI SECURITY does not
/// implement its own USB-malware scanner here — it manages the official
/// Windows setting that blocks the classic autorun.inf infection vector.
/// </summary>
public sealed class UsbAutoRunStatus
{
    public bool Available { get; init; }
    /// <summary>
    /// True when the NoDriveTypeAutoRun registry policy explicitly blocks
    /// removable drives; false when it explicitly allows them; null when no
    /// policy value is set at all. A null value does NOT mean "unprotected" —
    /// Windows has hard-coded autorun.inf execution off for non-optical
    /// removable media since a 2011 security update regardless of this key —
    /// BECETTI SECURITY only reports what the registry itself actually says.
    /// </summary>
    public bool? RemovableAutoRunBlocked { get; init; }
    /// <summary>True/false when NoAutorun is explicitly set; null when absent.</summary>
    public bool? AutorunInfDisabled { get; init; }
    /// <summary>True only when both values above are explicitly and verifiably set to block autorun.</summary>
    public bool FullyProtected => RemovableAutoRunBlocked == true && AutorunInfDisabled == true;
    public string? RawError { get; init; }
}

/// <summary>
/// One real network adapter from <see cref="System.Net.NetworkInformation.NetworkInterface"/> —
/// the same inventory Windows' own Network Connections panel is built on.
/// </summary>
public sealed class NetworkAdapterInfo
{
    public string Name { get; init; } = string.Empty;
    public string? Description { get; init; }
    public string InterfaceType { get; init; } = "Unknown";
    /// <summary>Raw OperationalStatus (e.g. "Up", "Down").</summary>
    public string Status { get; init; } = "Unknown";
    public bool IsUp { get; init; }
    /// <summary>Link speed in bits per second, or null when the adapter does not report one.</summary>
    public long? SpeedBps { get; init; }
    public string? MacAddress { get; init; }
    public IReadOnlyList<string> IPv4Addresses { get; init; } = Array.Empty<string>();
}

/// <summary>
/// One real active TCP connection or listening port from Get-NetTCPConnection —
/// the same source Resource Monitor's "Network" tab reads. The owning process
/// name is resolved from the real local process list; a connection whose
/// process already exited by the time it is resolved is shown with a null
/// name rather than a guessed one.
/// </summary>
public sealed class NetworkConnectionInfo
{
    public string LocalAddress { get; init; } = string.Empty;
    public int LocalPort { get; init; }
    public string? RemoteAddress { get; init; }
    public int RemotePort { get; init; }
    /// <summary>Raw TCP state (e.g. "Established", "Listen", "TimeWait").</summary>
    public string State { get; init; } = "Unknown";
    public int OwningProcessId { get; init; }
    public string? ProcessName { get; init; }

    /// <summary>Pre-formatted "address:port" for display, computed from real fields only.</summary>
    public string LocalEndpointDisplay => $"{LocalAddress}:{LocalPort}";
    public string RemoteEndpointDisplay =>
        string.IsNullOrWhiteSpace(RemoteAddress) || RemoteAddress == "0.0.0.0" || RemoteAddress == "::"
            ? "(listening)"
            : $"{RemoteAddress}:{RemotePort}";
    public string ProcessDisplay =>
        string.IsNullOrWhiteSpace(ProcessName) ? $"PID {OwningProcessId}" : $"{ProcessName} (PID {OwningProcessId})";
}

// ---------- Platform / Identity security (TPM, Secure Boot, Credential Guard, BitLocker, Windows Update) ----------

/// <summary>Real TPM state from the built-in Get-Tpm cmdlet.</summary>
public sealed class TpmStatus
{
    public bool Available { get; init; }
    public bool Present { get; init; }
    public bool Ready { get; init; }
    public string? ManufacturerVersion { get; init; }
    public string? RawError { get; init; }
}

/// <summary>Real UEFI Secure Boot state from Confirm-SecureBootUEFI. Unavailable on legacy BIOS systems.</summary>
public sealed class SecureBootStatus
{
    public bool Available { get; init; }
    public bool Enabled { get; init; }
    public string? RawError { get; init; }
}

/// <summary>Real Credential Guard running state from Win32_DeviceGuard (root\Microsoft\Windows\DeviceGuard).</summary>
public sealed class CredentialGuardStatus
{
    public bool Available { get; init; }
    public bool Running { get; init; }
    public string? RawError { get; init; }
}

/// <summary>Real BitLocker protection status for one volume from Get-BitLockerVolume.</summary>
public sealed class DiskEncryptionStatus
{
    public bool Available { get; init; }
    public string? MountPoint { get; init; }
    /// <summary>Raw BitLocker ProtectionStatus ("On"/"Off"), or null when unavailable.</summary>
    public string? ProtectionStatus { get; init; }
    public bool IsProtected => string.Equals(ProtectionStatus, "On", StringComparison.OrdinalIgnoreCase);
    public string? RawError { get; init; }
}

/// <summary>Real last-successful-install time from the Windows Update registry key Settings &gt; Update reads.</summary>
public sealed class WindowsUpdateStatus
{
    public bool Available { get; init; }
    public DateTimeOffset? LastSuccessInstallTime { get; init; }
}

/// <summary>One combined read of TPM, Secure Boot, Credential Guard and BitLocker state.</summary>
public sealed class PlatformSecuritySnapshot
{
    public TpmStatus Tpm { get; init; } = new();
    public SecureBootStatus SecureBoot { get; init; } = new();
    public CredentialGuardStatus CredentialGuard { get; init; } = new();
    public DiskEncryptionStatus DiskEncryption { get; init; } = new();
}

// ---------- Vulnerability Advisor / Security Reports shared findings ----------

/// <summary>Severity of one real, verified security finding. Never a guessed or simulated risk score.</summary>
public enum FindingSeverity
{
    Good,
    Info,
    Low,
    Medium,
    High,
    Unknown
}

/// <summary>
/// One real, verified security finding compiled from an existing BECETTI SECURITY
/// check (Defender, firewall, UAC, drivers, AutoRun, TPM, BitLocker, Windows Update).
/// BECETTI SECURITY has no vulnerability database or CVE feed of its own — every
/// finding here traces back to a real Windows/Defender API read elsewhere in the app.
/// </summary>
public sealed class SecurityFinding
{
    public string Title { get; init; } = string.Empty;
    public FindingSeverity Severity { get; init; } = FindingSeverity.Unknown;
    public string Detail { get; init; } = string.Empty;
    public string? Recommendation { get; init; }
    /// <summary>Which real API/cmdlet this finding came from, e.g. "Get-MpComputerStatus".</summary>
    public string Source { get; init; } = string.Empty;
}

// ---------- Browser Security ----------

/// <summary>One detected installed browser, reused from the real installed-software inventory.</summary>
public sealed class BrowserInfo
{
    public string Name { get; init; } = string.Empty;
    public string? Version { get; init; }
    public string? Publisher { get; init; }
}

/// <summary>Real Windows SmartScreen policy state read from the registry.</summary>
public sealed class SmartScreenStatus
{
    /// <summary>SmartScreen for apps &amp; files (Explorer). Null when not explicitly configured.</summary>
    public bool? AppsAndFilesEnabled { get; init; }
    /// <summary>Microsoft Edge's own SmartScreen policy. Null when not explicitly configured.</summary>
    public bool? EdgeSmartScreenEnabled { get; init; }
}

// ---------- Scheduled Scan ----------

/// <summary>
/// A real Windows Scheduled Task that BECETTI SECURITY registered to run an
/// unattended Defender scan (via MpCmdRun.exe), read back from Task Scheduler
/// itself (schtasks.exe /Query) — not an internal timer BECETTI SECURITY
/// fakes while the app is closed. Visible and manageable in Task Scheduler.
/// </summary>
public sealed class ScheduledScanInfo
{
    public bool Exists { get; init; }
    public string TaskName { get; init; } = string.Empty;
    public DefenderScanType ScanType { get; init; }
    public string? ScheduleDescription { get; init; }
    public DateTimeOffset? NextRunTime { get; init; }
    public DateTimeOffset? LastRunTime { get; init; }
    public string? LastTaskResult { get; init; }
}

// ---------- Wi-Fi Security ----------

/// <summary>Real currently-connected Wi-Fi network security details from "netsh wlan show interfaces".</summary>
public sealed class WifiSecurityInfo
{
    public bool Connected { get; init; }
    public string? Ssid { get; init; }
    /// <summary>Raw authentication type reported by Windows (e.g. "WPA2-Personal", "Open").</summary>
    public string? AuthenticationType { get; init; }
    public string? CipherType { get; init; }
    public int? SignalPercent { get; init; }
    /// <summary>True only when the authentication type is a recognized WPA2/WPA3 variant — never guessed.</summary>
    public bool? IsStronglySecured { get; init; }
    public string? RawError { get; init; }
}

// ---------- Backup Advisor ----------

/// <summary>
/// Real backup posture read from Windows' own File History configuration and
/// System Restore shadow copies (vssadmin/WMI). BECETTI SECURITY implements no
/// backup engine of its own — it only reports what Windows itself has configured.
/// </summary>
public sealed class BackupStatus
{
    public bool Available { get; init; }
    /// <summary>Null when File History's configuration could not be determined.</summary>
    public bool? FileHistoryConfigured { get; init; }
    public int RestorePointCount { get; init; }
    public DateTimeOffset? LatestRestorePoint { get; init; }
    public string? RawError { get; init; }
}

// ---------- Vulnerability Advisor report ----------

/// <summary>
/// A combined read of every real BECETTI SECURITY check compiled into one
/// list of findings. No independent vulnerability scanner or CVE feed is
/// implemented — this is a summary of checks that already exist elsewhere
/// in the app (Defender, firewall, USB AutoRun, drivers, platform security,
/// Windows Update).
/// </summary>
public sealed class VulnerabilityReport
{
    public IReadOnlyList<SecurityFinding> Findings { get; init; } = Array.Empty<SecurityFinding>();
    public int HighCount => Findings.Count(f => f.Severity == FindingSeverity.High);
    public int MediumCount => Findings.Count(f => f.Severity == FindingSeverity.Medium);
    public int LowCount => Findings.Count(f => f.Severity == FindingSeverity.Low);
    public int GoodCount => Findings.Count(f => f.Severity == FindingSeverity.Good);
    public DateTimeOffset GeneratedAt { get; init; } = DateTimeOffset.Now;
}

// ---------- Smart Security Reports ----------

/// <summary>
/// A single consolidated snapshot of the device's real security posture,
/// assembled from the same checks the other pages already perform (Defender,
/// firewall, PC health, vulnerability findings). Exportable as plain text or
/// a simple PDF so it can be shared or archived.
/// </summary>
public sealed class SecurityReportSummary
{
    public DateTimeOffset GeneratedAt { get; init; } = DateTimeOffset.Now;
    public string DeviceName { get; init; } = string.Empty;
    public bool DefenderAvailable { get; init; }
    public bool AntivirusEnabled { get; init; }
    public bool RealTimeProtectionEnabled { get; init; }
    public bool FirewallFullyEnabled { get; init; }
    public int ThreatCount { get; init; }
    public VulnerabilityReport Vulnerability { get; init; } = new();
}

// ---------- Cloud sync ----------

/// <summary>
/// Real cloud account/connectivity state built on top of the existing
/// ICloudService auth client — not a second backend. "Sync" here means the
/// local app's verified knowledge of the cloud account (reachability, signed
/// in email, last successful check), not a duplicated data store.
/// </summary>
public sealed class CloudSyncStatus
{
    public bool Configured { get; init; }
    public bool Reachable { get; init; }
    public bool Authenticated { get; init; }
    public string? AccountEmail { get; init; }
    public DateTimeOffset? LastSyncedAt { get; init; }
    public string? RawError { get; init; }
}

// ---------- Knowledge Base ----------

/// <summary>One locally-authored security education article (no external/AI content).</summary>
public sealed class KnowledgeBaseArticle
{
    public string Id { get; init; } = string.Empty;
    public string Title { get; init; } = string.Empty;
    public string Category { get; init; } = string.Empty;
    public string Body { get; init; } = string.Empty;
}

// ---------- Threat Intelligence (VirusTotal) ----------
// BECETTI SECURITY's core protection engine stays Microsoft Defender, read
// and managed only through Defender's own official interfaces. VirusTotal
// is an optional, clearly separate SECOND OPINION from ~70 third-party
// antivirus engines, reached only through BECETTI's own server-side proxy
// (see /backend/becetti-ai) so the VirusTotal API key never ships inside
// this app. Every value below is copied from VirusTotal's own real
// response — nothing here is simulated or backfilled.

/// <summary>What kind of target a VirusTotal check was for.</summary>
public enum ThreatIntelTargetType
{
    File,
    Url
}

/// <summary>The real, current state of a VirusTotal check, as reported by VirusTotal itself.</summary>
public enum ThreatIntelStatus
{
    /// <summary>Not yet submitted / unknown.</summary>
    Unknown,
    /// <summary>Hash lookup found no existing VirusTotal report; file content has not been uploaded.</summary>
    NotFound,
    /// <summary>Submitted to VirusTotal; the real scan is still running there.</summary>
    Queued,
    /// <summary>VirusTotal finished scanning and returned a real result.</summary>
    Completed,
    /// <summary>A real error occurred (network, rate limit, invalid key, etc.) — never a fabricated result.</summary>
    Error
}

/// <summary>Overall verdict as computed directly from VirusTotal's own detection stats.</summary>
public enum ThreatIntelVerdict
{
    Unknown,
    Clean,
    Suspicious,
    Malicious
}

/// <summary>One third-party engine's real verdict for this target, copied verbatim from VirusTotal.</summary>
public sealed class ThreatIntelEngineVerdict
{
    public string EngineName { get; init; } = string.Empty;
    /// <summary>VirusTotal's own category for this engine's verdict: "malicious" or "suspicious".</summary>
    public string Category { get; init; } = string.Empty;
    /// <summary>The engine's own label for the threat (e.g. "Trojan.GenericKD.12345"), when VirusTotal provides one.</summary>
    public string? Result { get; init; }
}

/// <summary>A completed or in-progress VirusTotal report for one file or URL.</summary>
public sealed class ThreatIntelReport
{
    public ThreatIntelStatus Status { get; init; } = ThreatIntelStatus.Unknown;
    public ThreatIntelTargetType TargetType { get; init; }
    public ThreatIntelVerdict Verdict { get; init; } = ThreatIntelVerdict.Unknown;

    /// <summary>VirusTotal analysis id, when a scan is queued or completed (used to poll for results).</summary>
    public string? AnalysisId { get; init; }

    public string? Sha256 { get; init; }
    public string? Url { get; init; }
    public string? FileName { get; init; }

    public int Malicious { get; init; }
    public int Suspicious { get; init; }
    public int Harmless { get; init; }
    public int Undetected { get; init; }
    public int Timeout { get; init; }
    public int TotalEngines { get; init; }

    /// <summary>e.g. "3/72" — malicious+suspicious over total engines that produced a verdict.</summary>
    public string DetectionRatio { get; init; } = "0/0";

    /// <summary>Only engines that flagged this target malicious or suspicious — never the full clean list.</summary>
    public IReadOnlyList<ThreatIntelEngineVerdict> FlaggedEngines { get; init; } = Array.Empty<ThreatIntelEngineVerdict>();

    public DateTimeOffset? ScanDateUtc { get; init; }

    /// <summary>Link to VirusTotal's own public report page for this item.</summary>
    public string? Permalink { get; init; }

    /// <summary>Human-readable message accompanying this state (e.g. why it is not found, or a real error).</summary>
    public string Message { get; init; } = string.Empty;
}

/// <summary>One locally-recorded, real VirusTotal check — BECETTI SECURITY's local scan history for this feature.</summary>
public sealed class ThreatIntelScanRecord
{
    public DateTimeOffset Timestamp { get; init; } = DateTimeOffset.UtcNow;
    public ThreatIntelTargetType TargetType { get; init; }
    /// <summary>File name or URL shown in the history list.</summary>
    public string TargetDisplay { get; init; } = string.Empty;
    public string? Sha256 { get; init; }
    public ThreatIntelVerdict Verdict { get; init; } = ThreatIntelVerdict.Unknown;
    public string DetectionRatio { get; init; } = "0/0";
    public string? Permalink { get; init; }
}

// ---------------------------------------------------------------------------
// Data Breach Monitoring (XposedOrNot for email, HIBP Pwned Passwords for
// password exposure) — an optional "has this shown up in a known public
// breach?" second opinion, independent of the core local AV engine, mirrored
// architecturally on the ThreatIntel* types above.
// ---------------------------------------------------------------------------

/// <summary>One real, named data breach that an email address was found in (from XposedOrNot).</summary>
public sealed class DataBreachRecord
{
    public string Name { get; init; } = string.Empty;
    public string? Domain { get; init; }
    public string? Industry { get; init; }
    public string? Description { get; init; }
    /// <summary>Categories of data this breach exposed (e.g. "Email addresses", "Passwords").</summary>
    public IReadOnlyList<string> ExposedData { get; init; } = Array.Empty<string>();
    /// <summary>Year (or date string) the breach occurred, as reported by the source.</summary>
    public string? BreachDate { get; init; }
    public long? RecordsExposed { get; init; }
    /// <summary>How crackable the exposed passwords were judged to be (e.g. "easytocrack", "hardtocrack", "unknown").</summary>
    public string? PasswordRisk { get; init; }
    public bool Verified { get; init; }
    public string? ReferenceUrl { get; init; }
}

/// <summary>Real result of checking an email address against known public data breaches.</summary>
public sealed class EmailBreachReport
{
    public string Email { get; init; } = string.Empty;
    public bool Breached { get; init; }
    public int BreachCount { get; init; }
    /// <summary>Every known breach this email appeared in — empty when not breached.</summary>
    public IReadOnlyList<DataBreachRecord> Breaches { get; init; } = Array.Empty<DataBreachRecord>();
    public string? RiskLabel { get; init; }
    public int? RiskScore { get; init; }
    public string Message { get; init; } = string.Empty;
    public DateTimeOffset CheckedUtc { get; init; } = DateTimeOffset.UtcNow;
}

/// <summary>
/// Real result of checking a password against HIBP's Pwned Passwords corpus.
/// The password itself is never transmitted anywhere — only a 5-character
/// SHA-1 prefix leaves the device; the exact match happens locally.
/// </summary>
public sealed class PasswordBreachReport
{
    public bool Breached { get; init; }
    /// <summary>How many times this exact password has been seen across known breaches.</summary>
    public long TimesSeen { get; init; }
    public string Message { get; init; } = string.Empty;
    public DateTimeOffset CheckedUtc { get; init; } = DateTimeOffset.UtcNow;
}

/// <summary>Kind of check recorded in the data-breach monitoring history.</summary>
public enum DataBreachCheckType
{
    Email = 0,
    Password = 1
}

/// <summary>
/// One locally-recorded breach-monitoring check. For password checks,
/// <see cref="TargetDisplay"/> is a fixed placeholder, never the password or
/// any part of its hash — nothing identifying the checked password is ever
/// persisted.
/// </summary>
public sealed class DataBreachCheckRecord
{
    public DateTimeOffset Timestamp { get; init; } = DateTimeOffset.UtcNow;
    public DataBreachCheckType CheckType { get; init; }
    /// <summary>The email address checked, or a fixed placeholder for password checks.</summary>
    public string TargetDisplay { get; init; } = string.Empty;
    public bool Breached { get; init; }
    /// <summary>Breach count (email checks) or times-seen count (password checks).</summary>
    public long Count { get; init; }

    /// <summary>UI convenience, not persisted: true when this check found nothing.</summary>
    [JsonIgnore]
    public bool IsClean => !Breached;

    /// <summary>UI convenience, not persisted: a short human-readable outcome for the history list.</summary>
    [JsonIgnore]
    public string StatusLabel => Breached ? $"Breached ({Count:N0})" : "Clean";
}
