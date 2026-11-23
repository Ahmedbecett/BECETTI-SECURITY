namespace Becetti.Security.Core.Models;

/// <summary>
/// Metadata and live installation state of an open-source or local Windows antivirus/detection engine.
/// Zero simulation: availability reflects an actual verified binary on disk.
/// </summary>
public sealed class AvEngineInfo
{
    public string EngineId { get; init; } = string.Empty;       // defender, yara, clamav, yarax, capa
    public string Name { get; init; } = string.Empty;
    public string VendorAndLicense { get; init; } = string.Empty;
    public string Description { get; init; } = string.Empty;
    public bool IsInstalled { get; init; }
    public bool CanAutoInstall { get; init; }
    public bool SupportsSignatureUpdate { get; init; }
    public string Version { get; init; } = "Not installed";
    public string ExecutablePath { get; init; } = string.Empty;
    public string StatusNote { get; init; } = string.Empty;

    public string StatusBadge => IsInstalled ? $"[READY · {Version}]" : "[NOT INSTALLED]";
    public string DisplayLine => $"{StatusBadge} {Name} ({VendorAndLicense}) — {StatusNote}";
}

/// <summary>
/// Result returned by a single antivirus/analysis engine for a scanned target.
/// </summary>
public sealed class SingleEngineVerdict
{
    public string EngineId { get; init; } = string.Empty;
    public string EngineName { get; init; } = string.Empty;
    public string Verdict { get; init; } = "Skipped"; // Clean, Malicious, Suspicious, Error, Skipped
    public bool ThreatDetected { get; init; }
    public string DetectionSummary { get; init; } = string.Empty;
    public IReadOnlyList<string> Indicators { get; init; } = Array.Empty<string>();
    public long DurationMs { get; init; }

    public string DisplayLine =>
        $"[{Verdict.ToUpperInvariant()}] {EngineName} ({DurationMs} ms) — {DetectionSummary}";
}

/// <summary>
/// Local VirusTotal-style Multi-Engine Open-Source Antivirus consensus report.
/// </summary>
public sealed class MultiEngineScanReport
{
    public string TargetPath { get; init; } = string.Empty;
    public string TargetSha256 { get; init; } = string.Empty;
    public DateTimeOffset ScannedAt { get; init; } = DateTimeOffset.UtcNow;
    public int EnginesExecuted { get; init; }
    public int EnginesFlagged { get; init; }
    public string OverallVerdict { get; init; } = "Clean"; // Clean, Suspicious, Malicious
    public IReadOnlyList<SingleEngineVerdict> EngineResults { get; init; } = Array.Empty<SingleEngineVerdict>();
    public IReadOnlyList<string> CapaCapabilities { get; init; } = Array.Empty<string>();
    public string Summary { get; init; } = string.Empty;
}
