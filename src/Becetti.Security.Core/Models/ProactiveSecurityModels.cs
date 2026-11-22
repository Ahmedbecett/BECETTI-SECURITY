namespace Becetti.Security.Core.Models;

// ── Feature #2: Browser Extensions Risk Auditor ──────────────────────────────────

public sealed class BrowserExtensionItem
{
    public string Browser { get; init; } = string.Empty; // Chrome, Edge, Brave, Firefox
    public string Profile { get; init; } = string.Empty;
    public string ExtensionId { get; init; } = string.Empty;
    public string Name { get; init; } = string.Empty;
    public string Version { get; init; } = string.Empty;
    public string ManifestPath { get; init; } = string.Empty;
    public IReadOnlyList<string> Permissions { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> RiskyPermissions { get; init; } = Array.Empty<string>();
    public string RiskLevel { get; init; } = "Low"; // Low, Medium, High, Critical
    public string RiskSummary { get; init; } = string.Empty;

    public string DisplayLine => $"[{RiskLevel}] {Browser} · {Name} v{Version}";
    public string DetailLine => string.IsNullOrWhiteSpace(RiskSummary) ? $"ID: {ExtensionId}" : RiskSummary;
}

public sealed class BrowserExtensionAuditReport
{
    public DateTimeOffset AuditedAt { get; init; } = DateTimeOffset.UtcNow;
    public int TotalExtensions { get; init; }
    public int HighRiskCount { get; init; }
    public int BrowsersInspected { get; init; }
    public IReadOnlyList<BrowserExtensionItem> Extensions { get; init; } = Array.Empty<BrowserExtensionItem>();
}

// ── Feature #3: Outdated Software & Winget Vulnerability Auditor ─────────────────

public sealed class OutdatedSoftwareItem
{
    public string Name { get; init; } = string.Empty;
    public string PackageId { get; init; } = string.Empty;
    public string InstalledVersion { get; init; } = string.Empty;
    public string AvailableVersion { get; init; } = string.Empty;
    public string Source { get; init; } = "winget";

    public string DisplayLine => $"{Name} ({InstalledVersion} -> {AvailableVersion})";
    public string DetailLine => $"Package ID: {PackageId} · Source: {Source}";
}

public sealed class SoftwareUpdateAuditReport
{
    public DateTimeOffset AuditedAt { get; init; } = DateTimeOffset.UtcNow;
    public bool WingetAvailable { get; init; }
    public int OutdatedCount { get; init; }
    public string Notes { get; init; } = string.Empty;
    public IReadOnlyList<OutdatedSoftwareItem> Packages { get; init; } = Array.Empty<OutdatedSoftwareItem>();
}

// ── Feature #4: Wi-Fi Security & ARP Spoofing / MITM Detector ────────────────────

public sealed class WifiSecurityInfo
{
    public bool IsConnected { get; init; }
    public string InterfaceName { get; init; } = string.Empty;
    public string Ssid { get; init; } = string.Empty;
    public string Bssid { get; init; } = string.Empty;
    public string Authentication { get; init; } = string.Empty;
    public string Cipher { get; init; } = string.Empty;
    public string RadioType { get; init; } = string.Empty;
    public string SignalStrength { get; init; } = string.Empty;
    public string RiskLevel { get; init; } = "Low"; // Low, Medium, High, Critical
    public string RiskReason { get; init; } = string.Empty;
}

public sealed class ArpEntryInfo
{
    public string IpAddress { get; init; } = string.Empty;
    public string MacAddress { get; init; } = string.Empty;
    public string EntryType { get; init; } = string.Empty;
    public bool IsGateway { get; init; }
    public bool IsSuspiciousDuplicate { get; init; }

    public string DisplayLine => $"{IpAddress}  ->  {MacAddress} ({EntryType})" + (IsGateway ? " [GATEWAY]" : "") + (IsSuspiciousDuplicate ? " [DUPLICATE MAC]" : "");
}

public sealed class WifiArpAuditReport
{
    public DateTimeOffset AuditedAt { get; init; } = DateTimeOffset.UtcNow;
    public WifiSecurityInfo Wifi { get; init; } = new();
    public string DefaultGatewayIp { get; init; } = string.Empty;
    public string DefaultGatewayMac { get; init; } = string.Empty;
    public bool ArpSpoofingSuspected { get; init; }
    public IReadOnlyList<string> Alerts { get; init; } = Array.Empty<string>();
    public IReadOnlyList<ArpEntryInfo> ArpEntries { get; init; } = Array.Empty<ArpEntryInfo>();
}

// ── Feature #5: Live Process DLL & Module Inspector ──────────────────────────────

public sealed class ProcessDllInfo
{
    public int ProcessId { get; init; }
    public string ProcessName { get; init; } = string.Empty;
    public string ModuleName { get; init; } = string.Empty;
    public string FilePath { get; init; } = string.Empty;
    public long SizeBytes { get; init; }
    public string SignatureStatus { get; init; } = "Unknown"; // Signed, Unsigned, Invalid
    public string Publisher { get; init; } = string.Empty;
    public string RiskLevel { get; init; } = "Low";
    public string RiskReason { get; init; } = string.Empty;

    public string DisplayLine => $"[{RiskLevel}] {ProcessName} (PID {ProcessId}) · {ModuleName} [{SignatureStatus}]";
    public string DetailLine => string.IsNullOrWhiteSpace(RiskReason) ? FilePath : $"{RiskReason} · {FilePath}";
}

public sealed class ProcessDllAuditReport
{
    public DateTimeOffset AuditedAt { get; init; } = DateTimeOffset.UtcNow;
    public int ProcessesScanned { get; init; }
    public int ModulesInspected { get; init; }
    public int UnsignedCount { get; init; }
    public int SuspiciousPathCount { get; init; }
    public IReadOnlyList<ProcessDllInfo> Modules { get; init; } = Array.Empty<ProcessDllInfo>();
}

// ── Feature #6: Secure File Shredder ─────────────────────────────────────────────

public sealed class FileShredReport
{
    public string OriginalPath { get; init; } = string.Empty;
    public long BytesOverwritten { get; init; }
    public int PassesCompleted { get; init; }
    public string Standard { get; init; } = "DoD 5220.22-M";
    public DateTimeOffset ShreddedAt { get; init; } = DateTimeOffset.UtcNow;
}

// ── Feature #7: k-Anonymity Password Breach & Strength Checker ───────────────────

public sealed class PasswordBreachReport
{
    public int Length { get; init; }
    public double EntropyBits { get; init; }
    public string StrengthRating { get; init; } = "Weak"; // Weak, Fair, Strong, Very Strong
    public bool BreachCheckSucceeded { get; init; }
    public bool IsCompromised { get; init; }
    public long BreachCount { get; init; }
    public string Sha1PrefixSent { get; init; } = string.Empty;
    public string Advice { get; init; } = string.Empty;
}

// ── Feature #8: Automated Scan Scheduler ─────────────────────────────────────────

public sealed class ScheduledScanResult
{
    public DateTimeOffset ExecutedAt { get; init; } = DateTimeOffset.UtcNow;
    public int HardeningScore { get; init; }
    public int YaraThreatsFound { get; init; }
    public string Summary { get; init; } = string.Empty;
}

// ── Feature #10: Executive HTML / Print-to-PDF Security Report ───────────────────

public sealed class SecurityReportResult
{
    public string ReportPath { get; init; } = string.Empty;
    public long SizeBytes { get; init; }
    public string Language { get; init; } = "en";
    public int SecurityScore { get; init; }
    public DateTimeOffset GeneratedAt { get; init; } = DateTimeOffset.UtcNow;
}

// ── Feature #11: Anti-Tamper App Lock Status ─────────────────────────────────────

public sealed class AppLockStatus
{
    public bool IsEnabled { get; init; }
    public bool HasPinConfigured { get; init; }
    public bool WindowsHelloSupported { get; init; }
}

// ── Feature #12: 7-Day Interactive Security Timeline Metric ──────────────────────

public sealed class DailySecurityMetric
{
    public string DayLabel { get; init; } = string.Empty;
    public int TotalCount { get; init; }
    public int AlertCount { get; init; }
    public double TotalBarHeight { get; init; }
    public double AlertBarHeight { get; init; }
    public string TooltipText => $"{DayLabel}: {TotalCount} total, {AlertCount} alerts";
}
