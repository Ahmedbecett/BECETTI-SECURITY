namespace Becetti.Security.Core.Models;

// ── Feature #1: MITRE ATT&CK Enterprise Reference ────────────────────────────────

public sealed class MitreAttackReference
{
    public string TechniqueId { get; init; } = string.Empty;   // e.g. T1059.001
    public string TechniqueName { get; init; } = string.Empty; // e.g. PowerShell
    public string Tactic { get; init; } = string.Empty;        // e.g. Execution
    public string Url { get; init; } = string.Empty;

    public string Badge => string.IsNullOrWhiteSpace(TechniqueId)
        ? string.Empty
        : $"[{TechniqueId} · {Tactic}] {TechniqueName}";
}

// ── Feature #2: Global Open Threat Intelligence Feeds (abuse.ch) ─────────────────

public sealed class ThreatFeedStatus
{
    public DateTimeOffset? LastSyncedUtc { get; init; }
    public int BotnetC2IpCount { get; init; }
    public int MaliciousDomainCount { get; init; }
    public int MalwareSha256Count { get; init; }
    public int TotalIndicators => BotnetC2IpCount + MaliciousDomainCount + MalwareSha256Count;
    public IReadOnlyList<string> SourcesLoaded { get; init; } = Array.Empty<string>();
    public string Summary { get; init; } = string.Empty;
}

public sealed class ThreatFeedMatch
{
    public string Indicator { get; init; } = string.Empty;
    public string IndicatorType { get; init; } = string.Empty; // IP, Domain, SHA256
    public string FeedSource { get; init; } = string.Empty;    // abuse.ch Feodo / URLhaus / MalwareBazaar
    public string Context { get; init; } = string.Empty;
    public MitreAttackReference Mitre { get; init; } = new();

    public string DisplayLine => $"[MATCH · {FeedSource}] {Indicator} ({IndicatorType}) · {Mitre.TechniqueId}";
}

// ── Feature #3: Live Outbound GeoIP Radar & 1-Click Firewall Block ───────────────

public sealed class OutboundConnectionIntel
{
    public int ProcessId { get; init; }
    public string ProcessName { get; init; } = string.Empty;
    public string ExecutablePath { get; init; } = string.Empty;
    public string RemoteIp { get; init; } = string.Empty;
    public int RemotePort { get; init; }
    public string State { get; init; } = string.Empty;
    public string Country { get; init; } = "Unknown";
    public string Organization { get; init; } = "Unknown";
    public bool IsThreatFeedMatch { get; init; }
    public string ThreatFeedSource { get; init; } = string.Empty;
    public string MitreTag { get; init; } = string.Empty;

    public bool CanBlockApp => !string.IsNullOrWhiteSpace(ExecutablePath) && File.Exists(ExecutablePath);

    public string DisplayLine =>
        (IsThreatFeedMatch ? "[C2 ALERT] " : "") +
        $"{ProcessName} (PID {ProcessId}) -> {RemoteIp}:{RemotePort} · {Country} ({Organization})";

    public string DetailLine =>
        IsThreatFeedMatch
            ? $"Threat Feed Match: {ThreatFeedSource} [{MitreTag}] · {ExecutablePath}"
            : string.IsNullOrWhiteSpace(ExecutablePath) ? $"State: {State}" : $"{State} · {ExecutablePath}";
}

public sealed class OutboundRadarReport
{
    public DateTimeOffset AuditedAt { get; init; } = DateTimeOffset.UtcNow;
    public int TotalExternalConnections { get; init; }
    public int UniqueCountries { get; init; }
    public int ThreatFeedMatches { get; init; }
    public IReadOnlyList<OutboundConnectionIntel> Connections { get; init; } = Array.Empty<OutboundConnectionIntel>();
}

// ── Feature #6: In-App GitHub Releases Auto-Updater ──────────────────────────────

public sealed class AppReleaseInfo
{
    public string CurrentVersion { get; init; } = "1.0.0";
    public string LatestTag { get; init; } = string.Empty;
    public string LatestVersion { get; init; } = string.Empty;
    public bool IsUpdateAvailable { get; init; }
    public DateTimeOffset? PublishedAt { get; init; }
    public string ReleaseNotes { get; init; } = string.Empty;
    public string ReleasePageUrl { get; init; } = string.Empty;
    public string MsixDownloadUrl { get; init; } = string.Empty;
    public string MsixFileName { get; init; } = string.Empty;
}

// ── Feature #8: Windows Privacy & Anti-Telemetry Hardener ────────────────────────

public sealed class PrivacyControlItem
{
    public string Id { get; init; } = string.Empty;
    public string Title { get; init; } = string.Empty;
    public string Description { get; init; } = string.Empty;
    public bool IsHardened { get; init; }
    public string CurrentState { get; init; } = string.Empty;
    public string RegistryLocation { get; init; } = string.Empty;

    public string StatusBadge => IsHardened ? "[HARDENED]" : "[DEFAULT]";
    public string DisplayLine => $"{StatusBadge} {Title} — {CurrentState}";
    public string ToggleButtonLabel => IsHardened ? "Revert to Default" : "Harden Now";
}

public sealed class PrivacyHardeningReport
{
    public DateTimeOffset AuditedAt { get; init; } = DateTimeOffset.UtcNow;
    public int HardenedCount { get; init; }
    public int TotalCount { get; init; }
    public int PrivacyScorePercent => TotalCount == 0 ? 0 : (int)Math.Round((HardenedCount / (double)TotalCount) * 100.0);
    public IReadOnlyList<PrivacyControlItem> Controls { get; init; } = Array.Empty<PrivacyControlItem>();
}
