namespace Becetti.Security.Core.Models;

/// <summary>An item encrypted and isolated inside BECETTI SECURITY's local AES-256-GCM quarantine vault.</summary>
public sealed class QuarantineEntry
{
    public string Id { get; init; } = string.Empty;
    public string OriginalPath { get; init; } = string.Empty;
    public string OriginalFileName { get; init; } = string.Empty;
    public string Sha256 { get; init; } = string.Empty;
    public long OriginalSizeBytes { get; init; }
    public string DetectionEngine { get; init; } = "YARA";
    public string RuleOrThreatName { get; init; } = string.Empty;
    public string Reason { get; init; } = string.Empty;
    public DateTimeOffset QuarantinedAt { get; init; } = DateTimeOffset.UtcNow;
    public string VaultFileName { get; init; } = string.Empty;

    public string SummaryLine =>
        $"{OriginalFileName} — {RuleOrThreatName} ({QuarantinedAt.LocalDateTime:g})";
}

/// <summary>Real Authenticode digital signature verification result for a Windows file.</summary>
public sealed class AuthenticodeInfo
{
    public bool IsSigned { get; init; }
    public bool IsTrusted { get; init; }
    public string Status { get; init; } = "Unknown";
    public string Subject { get; init; } = string.Empty;
    public string Issuer { get; init; } = string.Empty;
    public string Thumbprint { get; init; } = string.Empty;
    public DateTimeOffset? NotAfter { get; init; }
}

/// <summary>A single PE section header with its real Shannon entropy and RWX anomaly indicator.</summary>
public sealed class PeSectionInfo
{
    public string Name { get; init; } = string.Empty;
    public uint VirtualSize { get; init; }
    public uint RawSize { get; init; }
    public double Entropy { get; init; }
    public bool IsExecutable { get; init; }
    public bool IsWritable { get; init; }
    public bool IsHighEntropy => Entropy >= 7.2;
    public bool IsRwxAnomaly => IsExecutable && IsWritable;

    public string DisplayLine =>
        $"{Name,-10} | Raw: {RawSize:N0} B | Entropy: {Entropy:F2}" +
        (IsRwxAnomaly ? " [RWX!]" : string.Empty) +
        (IsHighEntropy ? " [PACKED/ENCRYPTED]" : string.Empty);
}

/// <summary>Real static PE, Shannon entropy, and Authenticode forensic report for any local file.</summary>
public sealed class FileForensicsReport
{
    public string FilePath { get; init; } = string.Empty;
    public string FileName { get; init; } = string.Empty;
    public long FileSizeBytes { get; init; }
    public string Sha256 { get; init; } = string.Empty;
    public double FileEntropy { get; init; }
    public bool IsLikelyPackedOrEncrypted => FileEntropy >= 7.2 || Sections.Any(s => s.IsHighEntropy);
    public bool IsPeBinary { get; init; }
    public string PeArchitecture { get; init; } = "Not a PE binary";
    public DateTimeOffset? PeCompileTimestampUtc { get; init; }
    public bool IsDll { get; init; }
    public IReadOnlyList<PeSectionInfo> Sections { get; init; } = Array.Empty<PeSectionInfo>();
    public IReadOnlyList<string> SuspiciousApis { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> PackerIndicators { get; init; } = Array.Empty<string>();
    public AuthenticodeInfo Signature { get; init; } = new();
    public string RiskAssessment { get; init; } = "Low";
    public IReadOnlyList<string> RiskReasons { get; init; } = Array.Empty<string>();
}

/// <summary>Event raised by Real-Time YARA Folder Guard when a newly created or modified file is scanned.</summary>
public sealed class RealTimeGuardEvent
{
    public DateTimeOffset Timestamp { get; init; } = DateTimeOffset.UtcNow;
    public string FilePath { get; init; } = string.Empty;
    public bool ThreatDetected { get; init; }
    public bool AutoQuarantined { get; init; }
    public string MatchedRulesSummary { get; init; } = string.Empty;
    public string Note { get; init; } = string.Empty;

    public string DisplayLine =>
        $"[{Timestamp.LocalDateTime:HH:mm:ss}] {(ThreatDetected ? "ALERT" : "CLEAN")} — {Path.GetFileName(FilePath)}: {MatchedRulesSummary}{(AutoQuarantined ? " [Quarantined]" : string.Empty)}";
}

/// <summary>A single running Windows process scanned in memory by native yara64.exe.</summary>
public sealed class YaraProcessMatch
{
    public int ProcessId { get; init; }
    public string ProcessName { get; init; } = string.Empty;
    public string? ExecutablePath { get; init; }
    public string RuleName { get; init; } = string.Empty;
    public string Description { get; init; } = string.Empty;
    public string Severity { get; init; } = "High";
    public IReadOnlyList<string> Tags { get; init; } = Array.Empty<string>();

    public string DisplayLine =>
        $"PID {ProcessId} ({ProcessName}) — {RuleName} [{Severity}]: {Description}";
}

/// <summary>Complete report of a live in-memory process scan executed via yara64.exe.</summary>
public sealed class YaraProcessScanReport
{
    public DateTimeOffset StartedAt { get; init; }
    public DateTimeOffset EndedAt { get; init; }
    public int ProcessesEnumerated { get; init; }
    public int ProcessesScanned { get; init; }
    public int ProcessesSkippedAccessDenied { get; init; }
    public bool WasCancelled { get; init; }
    public IReadOnlyList<YaraProcessMatch> Matches { get; init; } = Array.Empty<YaraProcessMatch>();
    public IReadOnlyList<string> Notes { get; init; } = Array.Empty<string>();
}

/// <summary>Status of an active Ransomware Canary honeypot decoy file.</summary>
public sealed class CanaryFileStatus
{
    public string FolderPath { get; init; } = string.Empty;
    public string FilePath { get; init; } = string.Empty;
    public string ExpectedSha256 { get; init; } = string.Empty;
    public bool IsIntact { get; init; } = true;
    public string StatusText { get; init; } = "Armed";
}

/// <summary>Alert raised immediately when a Ransomware Canary decoy file is modified, renamed, or deleted.</summary>
public sealed class CanaryAlertEvent
{
    public DateTimeOffset DetectedAt { get; init; } = DateTimeOffset.UtcNow;
    public string FilePath { get; init; } = string.Empty;
    public string ChangeType { get; init; } = string.Empty;
    public string Details { get; init; } = string.Empty;
}

/// <summary>Alert raised when Clipboard Hijack Guard detects a wallet/IBAN address swap.</summary>
public sealed class ClipboardHijackAlert
{
    public DateTimeOffset DetectedAt { get; init; } = DateTimeOffset.UtcNow;
    public string AssetType { get; init; } = string.Empty;
    public string OriginalValue { get; init; } = string.Empty;
    public string ReplacedValue { get; init; } = string.Empty;
    public string Message { get; init; } = string.Empty;
}

/// <summary>Result of an automatic YARA scan triggered on USB removable drive insertion.</summary>
public sealed class UsbAutoScanEvent
{
    public DateTimeOffset Timestamp { get; init; } = DateTimeOffset.UtcNow;
    public string DriveRoot { get; init; } = string.Empty;
    public string VolumeLabel { get; init; } = string.Empty;
    public int FilesScanned { get; init; }
    public int MatchesFound { get; init; }
    public string Summary { get; init; } = string.Empty;
}

/// <summary>An application blocked in Windows Firewall by BECETTI SECURITY.</summary>
public sealed class FirewallBlockedApp
{
    public string RuleName { get; init; } = string.Empty;
    public string ExecutablePath { get; init; } = string.Empty;
    public string Direction { get; init; } = "Outbound";
    public string DisplayLine => $"{Path.GetFileName(ExecutablePath)} ({Direction}) — {ExecutablePath}";
}

/// <summary>Persisted settings for Scheduled YARA Rule Auto-Updates.</summary>
public sealed class YaraUpdateScheduleConfig
{
    public bool Enabled { get; set; }
    public int IntervalHours { get; set; } = 24;
    public List<string> RepositoryIds { get; set; } = new() { "neo23x0-signature-base" };
    public DateTimeOffset? LastCheckedAt { get; set; }
    public DateTimeOffset? LastSuccessAt { get; set; }
    public string LastStatus { get; set; } = "Not run yet";
}
