namespace Becetti.Security.Core.Models;

// =========================================================================
//  #1: Local SIEM & Live Event Correlation Engine
// =========================================================================

public sealed class SiemEventEntry
{
    public DateTimeOffset Timestamp { get; init; } = DateTimeOffset.UtcNow;
    public string LogName { get; init; } = string.Empty;
    public int EventId { get; init; }
    public string Level { get; init; } = "Information";
    public string ProviderName { get; init; } = string.Empty;
    public string Message { get; init; } = string.Empty;
    public string MitreTechniqueId { get; init; } = string.Empty;

    public string DisplayLine =>
        $"[{Level}] [{LogName} #{EventId}] {Timestamp.ToLocalTime():yyyy-MM-dd HH:mm:ss} · {ProviderName}" +
        (string.IsNullOrWhiteSpace(MitreTechniqueId) ? "" : $" [{MitreTechniqueId}]");
}

public sealed class SiemCorrelationAlert
{
    public string RuleId { get; init; } = string.Empty;
    public string Title { get; init; } = string.Empty;
    public string Severity { get; init; } = "High";
    public string MitreTechniqueId { get; init; } = string.Empty;
    public int EventCount { get; init; }
    public string Evidence { get; init; } = string.Empty;
    public DateTimeOffset DetectedAt { get; init; } = DateTimeOffset.UtcNow;

    public string DisplayLine => $"[{Severity}] [{MitreTechniqueId}] {Title} ({EventCount} event(s)) — {Evidence}";
}

public sealed class SiemAuditReport
{
    public DateTimeOffset AuditedAt { get; init; } = DateTimeOffset.UtcNow;
    public int TotalEventsScanned { get; init; }
    public IReadOnlyList<SiemCorrelationAlert> Alerts { get; init; } = Array.Empty<SiemCorrelationAlert>();
    public IReadOnlyList<SiemEventEntry> RecentEvents { get; init; } = Array.Empty<SiemEventEntry>();
    public string Summary { get; init; } = string.Empty;
}

// =========================================================================
//  #2: LAN Device Discovery & Local Port Auditor
// =========================================================================

public sealed class LanDeviceInfo
{
    public string IpAddress { get; init; } = string.Empty;
    public string MacAddress { get; init; } = string.Empty;
    public string Vendor { get; init; } = "Unknown Vendor";
    public string Hostname { get; init; } = string.Empty;
    public string InterfaceType { get; init; } = "Dynamic";
    public bool RespondedToPing { get; init; }

    public string DisplayLine =>
        $"{IpAddress,-15} · {MacAddress,-17} · {Vendor}" +
        (string.IsNullOrWhiteSpace(Hostname) ? "" : $" · {Hostname}") +
        (RespondedToPing ? " [ONLINE]" : " [ARP]");
}

public sealed class ListeningPortInfo
{
    public string Protocol { get; init; } = "TCP";
    public string LocalAddress { get; init; } = string.Empty;
    public int LocalPort { get; init; }
    public int ProcessId { get; init; }
    public string ProcessName { get; init; } = string.Empty;
    public bool IsExposedToLan { get; init; }
    public string RiskTag => IsExposedToLan && LocalPort is 21 or 23 or 135 or 139 or 445 or 3389 or 5900
        ? "HIGH-EXPOSURE"
        : (IsExposedToLan ? "LAN-EXPOSED" : "LOCAL-ONLY");

    public string DisplayLine => $"[{RiskTag}] {Protocol} {LocalAddress}:{LocalPort} · {ProcessName} (PID {ProcessId})";
}

public sealed class LanAuditReport
{
    public DateTimeOffset AuditedAt { get; init; } = DateTimeOffset.UtcNow;
    public string LocalSubnet { get; init; } = string.Empty;
    public IReadOnlyList<LanDeviceInfo> Devices { get; init; } = Array.Empty<LanDeviceInfo>();
    public IReadOnlyList<ListeningPortInfo> ListeningPorts { get; init; } = Array.Empty<ListeningPortInfo>();
    public string Summary { get; init; } = string.Empty;
}

// =========================================================================
//  #3: Deep Privacy & Digital Traces Cleaner
// =========================================================================

public sealed class PrivacyTraceCategory
{
    public string Id { get; init; } = string.Empty;
    public string Name { get; init; } = string.Empty;
    public string Description { get; init; } = string.Empty;
    public int FileCount { get; init; }
    public long TotalBytes { get; init; }
    public bool IsSelected { get; set; } = true;
    public IReadOnlyList<string> TargetPaths { get; init; } = Array.Empty<string>();

    public string SizeFormatted => TotalBytes >= 1024L * 1024L
        ? $"{TotalBytes / (1024.0 * 1024.0):F2} MB"
        : $"{TotalBytes / 1024.0:F1} KB";

    public string DisplayLine => $"{Name} — {FileCount:N0} file(s) ({SizeFormatted})";
}

public sealed class PrivacyCleanResult
{
    public int FilesRemoved { get; init; }
    public long BytesReclaimed { get; init; }
    public bool DnsCacheFlushed { get; init; }
    public int SkippedLockedFiles { get; init; }
    public string Summary { get; init; } = string.Empty;
}

// =========================================================================
//  #4: SOAR Automated Incident Response Playbooks
// =========================================================================

public sealed class SoarPlaybookConfig
{
    public bool Enabled { get; set; }
    public bool AutoQuarantineOnCritical { get; set; } = true;
    public bool KillMaliciousProcess { get; set; } = true;
    public bool BlockExecutableInFirewall { get; set; } = true;
    public bool GenerateForensicEvidenceZip { get; set; } = true;
    public bool SendCriticalNotification { get; set; } = true;
}

public sealed class SoarExecutionReport
{
    public DateTimeOffset ExecutedAt { get; init; } = DateTimeOffset.UtcNow;
    public string TargetLabel { get; init; } = string.Empty;
    public bool AllStepsSucceeded { get; init; }
    public IReadOnlyList<string> StepLogs { get; init; } = Array.Empty<string>();
    public string? EvidenceZipPath { get; init; }
    public string Summary { get; init; } = string.Empty;
}

// =========================================================================
//  #5: Windows Root Certificate Store Auditor
// =========================================================================

public sealed class RootCertificateAuditItem
{
    public string StoreScope { get; init; } = string.Empty; // LocalMachine / CurrentUser
    public string Subject { get; init; } = string.Empty;
    public string Issuer { get; init; } = string.Empty;
    public string Thumbprint { get; init; } = string.Empty;
    public string SignatureAlgorithm { get; init; } = string.Empty;
    public DateTimeOffset NotBefore { get; init; }
    public DateTimeOffset NotAfter { get; init; }
    public bool IsExpired { get; init; }
    public bool IsWeakAlgorithm { get; init; }
    public bool IsUserInstalled { get; init; }
    public string RiskLevel { get; init; } = "Normal";
    public string RiskReason { get; init; } = string.Empty;

    public string DisplayLine =>
        $"[{RiskLevel}] [{StoreScope}] {Subject} · Alg: {SignatureAlgorithm} · Exp: {NotAfter:yyyy-MM-dd}" +
        (string.IsNullOrWhiteSpace(RiskReason) ? "" : $" · {RiskReason}");
}

public sealed class RootCertAuditReport
{
    public DateTimeOffset AuditedAt { get; init; } = DateTimeOffset.UtcNow;
    public int TotalRootCerts { get; init; }
    public int FlaggedCerts { get; init; }
    public IReadOnlyList<RootCertificateAuditItem> Items { get; init; } = Array.Empty<RootCertificateAuditItem>();
    public string Summary { get; init; } = string.Empty;
}

// =========================================================================
//  #6: Encrypted File & Folder Vault Pro
// =========================================================================

public sealed class VaultProItem
{
    public string Id { get; init; } = string.Empty;
    public string OriginalName { get; init; } = string.Empty;
    public bool IsFolderArchive { get; init; }
    public long PlaintextBytes { get; init; }
    public long EncryptedBytes { get; init; }
    public string Sha256 { get; init; } = string.Empty;
    public DateTimeOffset SealedAtUtc { get; init; } = DateTimeOffset.UtcNow;
    public string VaultFilePath { get; init; } = string.Empty;

    public string KindBadge => IsFolderArchive ? "[FOLDER-AES256]" : "[FILE-AES256]";
    public string DisplayLine => $"{KindBadge} {OriginalName} · {PlaintextBytes / 1024.0:F1} KB · Sealed {SealedAtUtc.ToLocalTime():g}";
}

// =========================================================================
//  #7: EML Email Phishing & Header Forensics Analyzer
// =========================================================================

public sealed class EmailForensicsReport
{
    public string FileName { get; init; } = string.Empty;
    public string FromHeader { get; init; } = string.Empty;
    public string ReplyToHeader { get; init; } = string.Empty;
    public string ReturnPathHeader { get; init; } = string.Empty;
    public string Subject { get; init; } = string.Empty;
    public string SpfStatus { get; init; } = "Not Present";
    public string DkimStatus { get; init; } = "Not Present";
    public string DmarcStatus { get; init; } = "Not Present";
    public int RiskScore { get; init; }
    public string Verdict { get; init; } = "Low Risk";
    public IReadOnlyList<string> ReceivedHops { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> ExtractedUrls { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> ThreatFeedHits { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> Findings { get; init; } = Array.Empty<string>();
    public string Summary { get; init; } = string.Empty;
}

// =========================================================================
//  #8: Live Process Tree & Parent-Child Anomaly Hunter
// =========================================================================

public sealed class ProcessTreeNode
{
    public int ProcessId { get; init; }
    public int ParentProcessId { get; init; }
    public string ProcessName { get; init; } = string.Empty;
    public string ParentName { get; init; } = string.Empty;
    public string ExecutablePath { get; init; } = string.Empty;
    public string CommandLine { get; init; } = string.Empty;
    public double MemoryMb { get; init; }
    public bool IsSigned { get; init; }
    public bool IsAnomaly { get; init; }
    public string AnomalyReason { get; init; } = string.Empty;
    public string MitreTechniqueId { get; init; } = string.Empty;

    public string DisplayLine =>
        (IsAnomaly ? $"[ANOMALY {(string.IsNullOrEmpty(MitreTechniqueId) ? "" : MitreTechniqueId + " ")}] " : "[OK] ") +
        $"{ParentName} -> {ProcessName} (PID {ProcessId}) · {MemoryMb:F1} MB · {(IsSigned ? "Signed" : "Unsigned")}" +
        (string.IsNullOrWhiteSpace(AnomalyReason) ? "" : $" · {AnomalyReason}");
}

public sealed class ProcessTreeReport
{
    public DateTimeOffset CapturedAt { get; init; } = DateTimeOffset.UtcNow;
    public int TotalProcesses { get; init; }
    public int AnomalyCount { get; init; }
    public IReadOnlyList<ProcessTreeNode> Processes { get; init; } = Array.Empty<ProcessTreeNode>();
    public string Summary { get; init; } = string.Empty;
}

// =========================================================================
//  #9: Local Sigma Rule Scanner
// =========================================================================

public sealed class SigmaRuleDefinition
{
    public string Id { get; init; } = string.Empty;
    public string Title { get; init; } = string.Empty;
    public string Level { get; init; } = "high";
    public string LogSource { get; init; } = "windows";
    public string MitreTechniqueId { get; init; } = string.Empty;
    public IReadOnlyList<string> KeywordsAny { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> KeywordsAll { get; init; } = Array.Empty<string>();
    public IReadOnlyList<int> EventIds { get; init; } = Array.Empty<int>();
    public string SourceFile { get; init; } = "Built-in";

    public string DisplayLine => $"[{Level.ToUpperInvariant()}] [{MitreTechniqueId}] {Title} ({SourceFile})";
}

public sealed class SigmaRuleMatch
{
    public string RuleTitle { get; init; } = string.Empty;
    public string Level { get; init; } = "high";
    public string MitreTechniqueId { get; init; } = string.Empty;
    public int EventId { get; init; }
    public string LogName { get; init; } = string.Empty;
    public DateTimeOffset Timestamp { get; init; }
    public string MatchedExcerpt { get; init; } = string.Empty;

    public string DisplayLine => $"[{Level.ToUpperInvariant()}] [{MitreTechniqueId}] {RuleTitle} · {LogName} #{EventId} ({Timestamp.ToLocalTime():HH:mm:ss})";
}

public sealed class SigmaScanReport
{
    public DateTimeOffset ScannedAt { get; init; } = DateTimeOffset.UtcNow;
    public int RulesEvaluated { get; init; }
    public int EventsEvaluated { get; init; }
    public IReadOnlyList<SigmaRuleMatch> Matches { get; init; } = Array.Empty<SigmaRuleMatch>();
    public string Summary { get; init; } = string.Empty;
}

// =========================================================================
//  #10: Live DNS Cache Threat Logger & Per-App Connection Auditor
// =========================================================================

public sealed class DnsCacheEntryIntel
{
    public string Domain { get; init; } = string.Empty;
    public string ResolvedData { get; init; } = string.Empty;
    public int TtlSeconds { get; init; }
    public bool IsMalicious { get; init; }
    public string ThreatSource { get; init; } = string.Empty;
    public string MitreTag { get; init; } = string.Empty;

    public string DisplayLine =>
        (IsMalicious ? $"[MALICIOUS {ThreatSource}] " : "[CLEAN] ") +
        $"{Domain} -> {ResolvedData} (TTL {TtlSeconds}s)";
}

public sealed class AppNetworkUsageSummary
{
    public int ProcessId { get; init; }
    public string ProcessName { get; init; } = string.Empty;
    public string ExecutablePath { get; init; } = string.Empty;
    public int ActiveConnections { get; init; }
    public int ExternalConnections { get; init; }
    public double WorkingSetMb { get; init; }
    public string TopRemoteEndpoints { get; init; } = string.Empty;

    public string DisplayLine =>
        $"{ProcessName} (PID {ProcessId}) · {ActiveConnections} conn ({ExternalConnections} ext) · RAM {WorkingSetMb:F1} MB · {TopRemoteEndpoints}";
}

public sealed class DnsAndAppNetworkReport
{
    public DateTimeOffset CapturedAt { get; init; } = DateTimeOffset.UtcNow;
    public int MaliciousDnsCount { get; init; }
    public IReadOnlyList<DnsCacheEntryIntel> DnsEntries { get; init; } = Array.Empty<DnsCacheEntryIntel>();
    public IReadOnlyList<AppNetworkUsageSummary> AppSummaries { get; init; } = Array.Empty<AppNetworkUsageSummary>();
    public string Summary { get; init; } = string.Empty;
}

// =========================================================================
//  #11: Multi-Device Cloud Fleet Dashboard
// =========================================================================

public sealed class FleetDeviceStatus
{
    public string DeviceId { get; init; } = string.Empty;
    public string DeviceName { get; init; } = string.Empty;
    public string OsVersion { get; init; } = string.Empty;
    public string AppVersion { get; init; } = string.Empty;
    public DateTimeOffset LastSeenUtc { get; init; }
    public bool IsCurrentDevice { get; init; }

    public string DisplayLine =>
        (IsCurrentDevice ? "[THIS PC] " : "[FLEET] ") +
        $"{DeviceName} · {OsVersion} · v{AppVersion} · Last seen {LastSeenUtc.ToLocalTime():g}";
}

public sealed class FleetDashboardReport
{
    public bool CloudConfigured { get; init; }
    public bool Authenticated { get; init; }
    public string CloudEndpoint { get; init; } = string.Empty;
    public int TotalDevices { get; init; }
    public IReadOnlyList<FleetDeviceStatus> Devices { get; init; } = Array.Empty<FleetDeviceStatus>();
    public string Summary { get; init; } = string.Empty;
}

// =========================================================================
//  #12: CIS Benchmark / NIST CSF / ISO 27001 Compliance Center
// =========================================================================

public sealed class ComplianceControlResult
{
    public string ControlId { get; init; } = string.Empty;
    public string Framework { get; init; } = string.Empty; // CIS Win11 / NIST CSF / ISO 27001
    public string Title { get; init; } = string.Empty;
    public string Status { get; init; } = "Pass"; // Pass / Fail / Warning
    public string Evidence { get; init; } = string.Empty;
    public string Remediation { get; init; } = string.Empty;

    public string DisplayLine => $"[{Status.ToUpperInvariant()}] [{Framework} · {ControlId}] {Title} — {Evidence}";
}

public sealed class ComplianceAuditReport
{
    public DateTimeOffset AuditedAt { get; init; } = DateTimeOffset.UtcNow;
    public string MachineName { get; init; } = Environment.MachineName;
    public int PassedCount { get; init; }
    public int FailedCount { get; init; }
    public int WarningCount { get; init; }
    public int ComplianceScorePercent { get; init; }
    public IReadOnlyList<ComplianceControlResult> Controls { get; init; } = Array.Empty<ComplianceControlResult>();
    public string Summary { get; init; } = string.Empty;
}
