using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

/// <summary>
/// Real, local native YARA malware-detection engine (https://github.com/VirusTotal/yara).
/// Executes the actual Windows x64 yara64.exe scanner and yarac64.exe compiler as managed,
/// isolated native processes — never simulated results, never a web link or external scan API.
/// </summary>
public interface IYaraEngineService
{
    /// <summary>Curated list of trusted open-source YARA rule repositories.</summary>
    IReadOnlyList<YaraTrustedRepository> TrustedRepositories { get; }

    /// <summary>Checks native YARA binaries (yara64.exe / yarac64.exe), version, and rule compilation state.</summary>
    Task<OperationResult<YaraEngineInfo>> GetEngineInfoAsync(CancellationToken ct = default);

    /// <summary>Ensures bundled verified rules are copied into the local rules directory and compiled.</summary>
    Task<OperationResult<YaraEngineInfo>> InitializeAsync(CancellationToken ct = default);

    /// <summary>Lists all managed .yar and .yara rule files (bundled, user-imported, and repository-updated).</summary>
    Task<OperationResult<IReadOnlyList<YaraRuleFileInfo>>> GetRuleFilesAsync(CancellationToken ct = default);

    /// <summary>Validates a single .yar or .yara file with yarac64.exe before loading it into the engine.</summary>
    Task<OperationResult<YaraRuleValidationResult>> ValidateRuleFileAsync(string ruleFilePath, CancellationToken ct = default);

    /// <summary>Validates and imports a local .yar or .yara file; rejects invalid rules without affecting existing rules.</summary>
    Task<OperationResult<YaraRuleFileInfo>> ImportRuleFileAsync(string sourceFilePath, CancellationToken ct = default);

    /// <summary>Enables or disables a rule file and recompiles the active YARA rules bundle.</summary>
    Task<OperationResult<YaraEngineInfo>> SetRuleEnabledAsync(string ruleId, bool enabled, CancellationToken ct = default);

    /// <summary>Removes a user or repository rule file and recompiles the active YARA rules bundle.</summary>
    Task<OperationResult<YaraEngineInfo>> RemoveRuleFileAsync(string ruleId, CancellationToken ct = default);

    /// <summary>Validates every enabled rule file individually, isolates invalid/outdated ones, and compiles all valid rules.</summary>
    Task<OperationResult<YaraEngineInfo>> RebuildCompiledRulesAsync(CancellationToken ct = default);

    /// <summary>Scans a single file or directory recursively using the compiled native YARA rules.</summary>
    Task<OperationResult<YaraScanReport>> ScanAsync(
        string targetPath,
        IProgress<YaraScanProgress>? progress = null,
        CancellationToken ct = default);

    /// <summary>Scans a list of files or folders (e.g. Downloads, Desktop, Temp) using the native YARA engine.</summary>
    Task<OperationResult<YaraScanReport>> ScanTargetsAsync(
        IReadOnlyList<string> targetPaths,
        string displayLabel,
        IProgress<YaraScanProgress>? progress = null,
        CancellationToken ct = default);

    /// <summary>Downloads rules from a trusted repository, validates each file with yarac64.exe, and activates only valid rules.</summary>
    Task<OperationResult<YaraRuleUpdateResult>> UpdateRulesFromRepositoryAsync(
        string repositoryId,
        CancellationToken ct = default);

    /// <summary>Downloads a single .yar/.yara file over HTTPS, validates it with yarac64.exe, and activates it only if valid.</summary>
    Task<OperationResult<YaraRuleUpdateResult>> UpdateRuleFromHttpsUrlAsync(
        string ruleUrl,
        CancellationToken ct = default);

    /// <summary>Scans a single live Windows process in memory via native yara64.exe &lt;rules&gt; &lt;PID&gt;.</summary>
    Task<OperationResult<YaraProcessScanReport>> ScanProcessAsync(int processId, CancellationToken ct = default);

    /// <summary>Scans accessible running Windows processes in memory via native yara64.exe.</summary>
    Task<OperationResult<YaraProcessScanReport>> ScanRunningProcessesAsync(
        IProgress<YaraScanProgress>? progress = null,
        CancellationToken ct = default);

    /// <summary>Formats a real scan report as a human-readable plain-text report (including YARA license notice).</summary>
    string FormatReportAsText(YaraScanReport report);

    /// <summary>Formats a real scan report as indented JSON.</summary>
    string FormatReportAsJson(YaraScanReport report);

    /// <summary>Formats a real scan report as a self-contained PDF document.</summary>
    byte[] FormatReportAsPdf(YaraScanReport report);
}
