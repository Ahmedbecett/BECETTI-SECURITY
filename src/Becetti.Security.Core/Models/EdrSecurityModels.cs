namespace Becetti.Security.Core.Models;

// =========================================================================
// 1. Deep Persistence Hunter (Autoruns Pro)
// =========================================================================

public sealed class PersistenceEntry
{
    public string Category { get; init; } = string.Empty; // ScheduledTask, Service, Winlogon, IfeoDebugger, AppInitDll
    public string Name { get; init; } = string.Empty;
    public string SourceLocation { get; init; } = string.Empty;
    public string Command { get; init; } = string.Empty;
    public string? ExecutablePath { get; init; }
    public string SignatureStatus { get; init; } = "Unknown"; // Signed, Unsigned, Invalid, Missing, NotChecked
    public string? Publisher { get; init; }
    public string RiskLevel { get; init; } = "Low"; // Low, Medium, High, Critical
    public string RiskReason { get; init; } = string.Empty;
    public bool CanDisable { get; init; }

    public string SummaryLine =>
        $"[{RiskLevel}] {Category} · {Name} · Sig: {SignatureStatus}" +
        (string.IsNullOrWhiteSpace(Publisher) ? string.Empty : $" ({Publisher})");
}

public sealed class PersistenceAuditReport
{
    public DateTimeOffset AuditedAt { get; init; } = DateTimeOffset.UtcNow;
    public int TotalInspected { get; init; }
    public int HighRiskCount { get; init; }
    public int UnsignedCount { get; init; }
    public IReadOnlyList<PersistenceEntry> Entries { get; init; } = Array.Empty<PersistenceEntry>();
}

// =========================================================================
// 2. Hosts File & DNS Hijack Guard
// =========================================================================

public enum DnsProtectionPreset
{
    CloudflareMalware, // 1.1.1.2 / 1.0.0.2
    Quad9Secure,       // 9.9.9.9 / 149.112.112.112
    AutomaticDhcp      // Restore automatic DHCP DNS
}

public sealed class HostsMappingEntry
{
    public int LineNumber { get; init; }
    public string IpAddress { get; init; } = string.Empty;
    public string Hostname { get; init; } = string.Empty;
    public bool IsSuspicious { get; init; }
    public string SuspicionReason { get; init; } = string.Empty;

    public string DisplayLine =>
        $"L{LineNumber}: {IpAddress} -> {Hostname}" +
        (IsSuspicious ? $"  [!] {SuspicionReason}" : string.Empty);
}

public sealed class AdapterDnsInfo
{
    public string InterfaceName { get; init; } = string.Empty;
    public string Status { get; init; } = string.Empty;
    public IReadOnlyList<string> DnsServers { get; init; } = Array.Empty<string>();
    public string DisplayLine => $"{InterfaceName} ({Status}): {(DnsServers.Count == 0 ? "Auto / None" : string.Join(", ", DnsServers))}";
}

public sealed class HostsDnsAuditReport
{
    public DateTimeOffset CheckedAt { get; init; } = DateTimeOffset.UtcNow;
    public string HostsFilePath { get; init; } = string.Empty;
    public bool HostsFileExists { get; init; }
    public string HostsSha256 { get; init; } = string.Empty;
    public int TotalMappings { get; init; }
    public int SuspiciousMappings { get; init; }
    public IReadOnlyList<HostsMappingEntry> Mappings { get; init; } = Array.Empty<HostsMappingEntry>();
    public IReadOnlyList<AdapterDnsInfo> Adapters { get; init; } = Array.Empty<AdapterDnsInfo>();
}

public sealed class HostsTamperAlert
{
    public DateTimeOffset Timestamp { get; init; } = DateTimeOffset.UtcNow;
    public string HostsFilePath { get; init; } = string.Empty;
    public string PreviousSha256 { get; init; } = string.Empty;
    public string NewSha256 { get; init; } = string.Empty;
    public string Message { get; init; } = string.Empty;
}

// =========================================================================
// 3. Camera & Microphone Access Auditor
// =========================================================================

public sealed class DevicePrivacyAccessEntry
{
    public string Capability { get; init; } = string.Empty; // Camera, Microphone
    public string AppName { get; init; } = string.Empty;
    public string Identifier { get; init; } = string.Empty;
    public bool IsPackaged { get; init; }
    public bool IsActiveNow { get; init; }
    public DateTimeOffset? LastUsedStart { get; init; }
    public DateTimeOffset? LastUsedStop { get; init; }

    public string DisplayLine =>
        (IsActiveNow ? "[LIVE] " : "") +
        $"{Capability} · {AppName} · " +
        (IsActiveNow
            ? "ACTIVE RIGHT NOW"
            : LastUsedStart.HasValue
                ? $"Last used {LastUsedStart.Value.ToLocalTime():yyyy-MM-dd HH:mm}"
                : "Never used");
}

public sealed class CameraMicAuditReport
{
    public DateTimeOffset AuditedAt { get; init; } = DateTimeOffset.UtcNow;
    public int ActiveCameraApps { get; init; }
    public int ActiveMicrophoneApps { get; init; }
    public IReadOnlyList<DevicePrivacyAccessEntry> Entries { get; init; } = Array.Empty<DevicePrivacyAccessEntry>();
}

// =========================================================================
// 4. Suspicious PowerShell & LOLBins Script Auditor
// =========================================================================

public sealed class SuspiciousScriptEvent
{
    public DateTimeOffset Timestamp { get; init; } = DateTimeOffset.UtcNow;
    public string Source { get; init; } = string.Empty; // Process, PowerShell-4104
    public string ProcessOrHost { get; init; } = string.Empty;
    public string RawCommand { get; init; } = string.Empty;
    public string? DecodedBase64 { get; init; }
    public IReadOnlyList<string> MatchedIndicators { get; init; } = Array.Empty<string>();
    public string RiskLevel { get; init; } = "Medium";

    public string DisplayLine =>
        $"[{RiskLevel}] {Timestamp.ToLocalTime():HH:mm:ss} · {Source} · {ProcessOrHost} · {string.Join(", ", MatchedIndicators)}";
}

public sealed class ScriptAuditReport
{
    public DateTimeOffset AuditedAt { get; init; } = DateTimeOffset.UtcNow;
    public int RunningProcessesChecked { get; init; }
    public int EventLogBlocksChecked { get; init; }
    public IReadOnlyList<SuspiciousScriptEvent> Findings { get; init; } = Array.Empty<SuspiciousScriptEvent>();
    public string Note { get; init; } = string.Empty;
}

// =========================================================================
// 5. Phishing & Homograph URL Inspector
// =========================================================================

public sealed class UrlInspectionReport
{
    public DateTimeOffset InspectedAt { get; init; } = DateTimeOffset.UtcNow;
    public string OriginalUrl { get; init; } = string.Empty;
    public string Host { get; init; } = string.Empty;
    public string PunycodeHost { get; init; } = string.Empty;
    public bool UsesHttps { get; init; }
    public bool IsHomographSuspected { get; init; }
    public string HomographReason { get; init; } = string.Empty;
    public IReadOnlyList<string> RedirectChain { get; init; } = Array.Empty<string>();
    public bool TlsInspected { get; init; }
    public bool TlsValid { get; init; }
    public string TlsSubject { get; init; } = string.Empty;
    public string TlsIssuer { get; init; } = string.Empty;
    public DateTimeOffset? TlsNotAfter { get; init; }
    public int TlsDaysRemaining { get; init; }
    public int RiskScore { get; init; } // 0-100
    public string RiskLevel { get; init; } = "Low";
    public IReadOnlyList<string> Findings { get; init; } = Array.Empty<string>();
}

// =========================================================================
// 6. Network Kill-Switch / Host Isolation
// =========================================================================

public sealed class NetworkIsolationStatus
{
    public bool IsIsolated { get; init; }
    public DateTimeOffset CheckedAt { get; init; } = DateTimeOffset.UtcNow;
    public string Summary { get; init; } = string.Empty;
}

// =========================================================================
// 7. Forensic Incident Evidence Bundle (ZIP)
// =========================================================================

public sealed class IncidentBundleResult
{
    public string BundleZipPath { get; init; } = string.Empty;
    public long SizeBytes { get; init; }
    public string Sha256 { get; init; } = string.Empty;
    public DateTimeOffset GeneratedAt { get; init; } = DateTimeOffset.UtcNow;
    public IReadOnlyList<string> IncludedArtifacts { get; init; } = Array.Empty<string>();
}

// =========================================================================
// 8. File Integrity Monitor (FIM)
// =========================================================================

public sealed class FimBaselineEntry
{
    public string FilePath { get; set; } = string.Empty;
    public string BaselineSha256 { get; set; } = string.Empty;
    public long BaselineSizeBytes { get; set; }
    public DateTimeOffset BaselineCreatedAt { get; set; } = DateTimeOffset.UtcNow;
}

public sealed class FimCheckItem
{
    public string FilePath { get; init; } = string.Empty;
    public string BaselineSha256 { get; init; } = string.Empty;
    public string CurrentSha256 { get; init; } = string.Empty;
    public string Status { get; init; } = "Intact"; // Intact, Modified, Missing, Error
    public string Detail { get; init; } = string.Empty;
    public DateTimeOffset CheckedAt { get; init; } = DateTimeOffset.UtcNow;

    public string DisplayLine => $"[{Status}] {Path.GetFileName(FilePath)} · {Detail}";
}

public sealed class FimCheckReport
{
    public DateTimeOffset CheckedAt { get; init; } = DateTimeOffset.UtcNow;
    public int TotalTracked { get; init; }
    public int IntactCount { get; init; }
    public int ModifiedCount { get; init; }
    public int MissingCount { get; init; }
    public IReadOnlyList<FimCheckItem> Items { get; init; } = Array.Empty<FimCheckItem>();
}

public sealed class FimViolationAlert
{
    public DateTimeOffset Timestamp { get; init; } = DateTimeOffset.UtcNow;
    public string FilePath { get; init; } = string.Empty;
    public string ChangeType { get; init; } = string.Empty;
    public string ExpectedSha256 { get; init; } = string.Empty;
    public string ActualSha256 { get; init; } = string.Empty;
}

// =========================================================================
// 9. Windows Hardening & Attack Surface Auditor
// =========================================================================

public sealed class HardeningCheckItem
{
    public string Id { get; init; } = string.Empty;
    public string Category { get; init; } = string.Empty;
    public string Title { get; init; } = string.Empty;
    public string Status { get; init; } = "Unavailable"; // Passed, Warning, Failed, Unavailable
    public string CurrentValue { get; init; } = string.Empty;
    public string Recommendation { get; init; } = string.Empty;
    public bool CanAutoFix { get; init; }
    public string AutoFixAction { get; init; } = string.Empty;

    public string DisplayLine => $"[{Status}] {Title} — {CurrentValue}";
}

public sealed class WindowsHardeningReport
{
    public DateTimeOffset AuditedAt { get; init; } = DateTimeOffset.UtcNow;
    public int ScorePercent { get; init; }
    public int PassedCount { get; init; }
    public int WarningCount { get; init; }
    public int FailedCount { get; init; }
    public int TotalEvaluated { get; init; }
    public IReadOnlyList<HardeningCheckItem> Checks { get; init; } = Array.Empty<HardeningCheckItem>();
}
