namespace Becetti.Security.Core.Models;

/// <summary>Live status of the local native YARA engine (yara64.exe / yarac64.exe).</summary>
public sealed class YaraEngineInfo
{
    public bool IsAvailable { get; init; }
    public string? YaraExecutablePath { get; init; }
    public string? YaracExecutablePath { get; init; }
    public string? Version { get; init; }
    public string Architecture { get; init; } = Environment.Is64BitOperatingSystem ? "win-x64" : "win-x86";
    public string? BuildOrigin { get; init; }
    public string? Error { get; init; }
    public int TotalRuleFiles { get; init; }
    public int ValidRuleFiles { get; init; }
    public int InvalidRuleFiles { get; init; }
    public int DisabledRuleFiles { get; init; }
    public int ActiveRuleCount { get; init; }
    public bool CompiledBundleReady { get; init; }
    public DateTimeOffset? LastCompiledAt { get; init; }
    public string LicenseNotice { get; init; } =
        "Powered by YARA (https://github.com/VirusTotal/yara) — Copyright (c) 2007-2016 The YARA Authors. Licensed under the BSD 3-Clause License.";
}

public enum YaraRuleSource
{
    Bundled,
    User,
    Repository
}

public enum YaraRuleValidationStatus
{
    Unknown,
    Valid,
    Invalid,
    Disabled
}

/// <summary>Metadata and validation state of a single .yar / .yara rule file managed by BECETTI SECURITY.</summary>
public sealed class YaraRuleFileInfo
{
    public string Id { get; init; } = string.Empty;
    public string FileName { get; init; } = string.Empty;
    public string FullPath { get; init; } = string.Empty;
    public YaraRuleSource Source { get; init; }
    public string SourceName { get; init; } = string.Empty;
    public bool IsEnabled { get; set; } = true;
    public YaraRuleValidationStatus Status { get; set; } = YaraRuleValidationStatus.Unknown;
    public int RuleCount { get; set; }
    public IReadOnlyList<string> RuleNames { get; set; } = Array.Empty<string>();
    public string? ValidationError { get; set; }
    public DateTimeOffset? LastValidatedAt { get; set; }
    public long FileSizeBytes { get; init; }
    public string Sha256 { get; init; } = string.Empty;

    public bool CanDelete => Source != YaraRuleSource.Bundled;

    public string StatusSummary => Status switch
    {
        YaraRuleValidationStatus.Valid => $"Valid ({RuleCount} rule{(RuleCount == 1 ? "" : "s")})",
        YaraRuleValidationStatus.Invalid => $"Invalid — excluded from scanner ({ValidationError ?? "compile error"})",
        YaraRuleValidationStatus.Disabled => "Disabled",
        _ => "Not validated yet"
    };
}

/// <summary>Result of validating/compiling a single .yar / .yara rule file with yarac64.exe.</summary>
public sealed class YaraRuleValidationResult
{
    public string FilePath { get; init; } = string.Empty;
    public bool IsValid { get; init; }
    public int RuleCount { get; init; }
    public IReadOnlyList<string> RuleNames { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();
    public string? ErrorMessage { get; init; }
    public TimeSpan Duration { get; init; }
}

/// <summary>A single matched string/pattern occurrence reported by yara64.exe -s.</summary>
public sealed class YaraMatchedString
{
    public string Offset { get; init; } = string.Empty;
    public string Identifier { get; init; } = string.Empty;
    public string Preview { get; init; } = string.Empty;

    public string DisplayLine => $"{Offset} {Identifier}: {Preview}";
}

/// <summary>A real detection emitted by the local native YARA engine against a scanned file.</summary>
public sealed class YaraRuleMatch
{
    public string RuleName { get; init; } = string.Empty;
    public string FilePath { get; init; } = string.Empty;
    public string Description { get; init; } = string.Empty;
    public string Author { get; init; } = string.Empty;
    public string Severity { get; init; } = "Medium";
    public string Category { get; init; } = "Suspicious";
    public string Reference { get; init; } = string.Empty;
    public IReadOnlyList<string> Tags { get; init; } = Array.Empty<string>();
    public IReadOnlyDictionary<string, string> Metadata { get; init; } = new Dictionary<string, string>();
    public IReadOnlyList<YaraMatchedString> MatchedStrings { get; init; } = Array.Empty<YaraMatchedString>();

    public string TagsText => Tags.Count == 0 ? string.Empty : string.Join(", ", Tags);
    public string MatchedStringsText => MatchedStrings.Count == 0
        ? string.Empty
        : string.Join(Environment.NewLine, MatchedStrings.Take(8).Select(s => s.DisplayLine));
}

/// <summary>Real-time progress snapshot during an active local YARA scan.</summary>
public sealed class YaraScanProgress
{
    public int FilesScanned { get; init; }
    public int TotalFiles { get; init; }
    public int MatchesFound { get; init; }
    public int ErrorsCount { get; init; }
    public string CurrentFile { get; init; } = string.Empty;
    public TimeSpan Elapsed { get; init; }
    public double PercentComplete => TotalFiles <= 0 ? 0 : Math.Min(100.0, FilesScanned * 100.0 / TotalFiles);
}

/// <summary>An honest per-file or engine error recorded during scanning (never hidden).</summary>
public sealed class YaraScanError
{
    public string FilePath { get; init; } = string.Empty;
    public string Code { get; init; } = string.Empty;
    public string Message { get; init; } = string.Empty;

    public string DisplayLine => string.IsNullOrWhiteSpace(FilePath)
        ? $"[{Code}] {Message}"
        : $"{FilePath} — [{Code}] {Message}";
}

/// <summary>Complete report produced by a real local YARA scan.</summary>
public sealed class YaraScanReport
{
    public string ScanId { get; init; } = Guid.NewGuid().ToString("N")[..12].ToUpperInvariant();
    public string TargetPath { get; init; } = string.Empty;
    public DateTimeOffset StartedAt { get; init; }
    public DateTimeOffset EndedAt { get; init; }
    public TimeSpan Duration => EndedAt - StartedAt;
    public string EngineVersion { get; init; } = string.Empty;
    public int ActiveRuleFilesCount { get; init; }
    public int TotalRulesLoaded { get; init; }
    public int FilesScanned { get; init; }
    public int FilesSkipped { get; init; }
    public bool WasCancelled { get; init; }
    public IReadOnlyList<YaraRuleMatch> Matches { get; init; } = Array.Empty<YaraRuleMatch>();
    public IReadOnlyList<YaraScanError> Errors { get; init; } = Array.Empty<YaraScanError>();

    public bool ThreatFound => Matches.Count > 0;
}

/// <summary>A curated, trusted open-source YARA rule repository.</summary>
public sealed class YaraTrustedRepository
{
    public string Id { get; init; } = string.Empty;
    public string Name { get; init; } = string.Empty;
    public string Description { get; init; } = string.Empty;
    public string RepositoryUrl { get; init; } = string.Empty;
    public string License { get; init; } = string.Empty;
    public IReadOnlyList<string> RuleFileUrls { get; init; } = Array.Empty<string>();
}

/// <summary>Result of updating YARA rules from a trusted repository or HTTPS URL.</summary>
public sealed class YaraRuleUpdateResult
{
    public string SourceName { get; init; } = string.Empty;
    public int AttemptedCount { get; init; }
    public int ValidatedAndImportedCount { get; init; }
    public int RejectedCount { get; init; }
    public IReadOnlyList<string> ImportedFiles { get; init; } = Array.Empty<string>();
    public IReadOnlyDictionary<string, string> RejectedFiles { get; init; } = new Dictionary<string, string>();
    public DateTimeOffset CompletedAt { get; init; } = DateTimeOffset.UtcNow;
}
