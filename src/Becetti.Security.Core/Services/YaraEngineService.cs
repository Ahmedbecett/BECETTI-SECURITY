using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

/// <summary>
/// Real, local native YARA engine integration for BECETTI SECURITY.
/// Uses VirusTotal's official YARA x64 native binaries (yara64.exe &amp; yarac64.exe)
/// via managed process isolation:
/// - Every .yar / .yara rule file is validated individually with yarac64.exe BEFORE loading.
/// - Invalid, corrupt, or outdated rules (including rules using unsupported modules) are
///   isolated with their exact compiler diagnostics and NEVER break the scanner.
/// - Valid rules are compiled into a binary .yarc bundle with unique per-file namespaces
///   so rule names across different files never collide.
/// - File and directory scans execute yara64.exe locally with -C -m -s -g and return
///   100% real detection verdicts, rule descriptions, metadata, tags, and matched indicators.
/// </summary>
public sealed class YaraEngineService : IYaraEngineService
{
    private const int MaxRuleFileDownloadBytes = 2 * 1024 * 1024; // 2 MB per remote rule file
    private const int MaxScanFileBytes = 100 * 1024 * 1024; // Skip single files > 100 MB with honest warning
    private static readonly TimeSpan VersionTimeout = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan CompileTimeout = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan SingleFileScanTimeout = TimeSpan.FromSeconds(30);

    private static readonly Regex RuleDeclarationRegex = new(
        @"^\s*(?:(?:private|global)\s+)*rule\s+([A-Za-z_][A-Za-z0-9_]*)",
        RegexOptions.Multiline | RegexOptions.Compiled);

    private static readonly Regex MatchedStringLineRegex = new(
        @"^(0x[0-9a-fA-F]+):(\$[A-Za-z0-9_]*):\s*(.*)$",
        RegexOptions.Compiled);

    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    private readonly HttpClient _http;
    private readonly ISettingsService _settings;
    private readonly string? _explicitYaraPath;
    private readonly string? _explicitYaracPath;
    private readonly string? _explicitBundledRulesDir;
    private readonly SemaphoreSlim _rulesLock = new(1, 1);

    private string? _cachedVersion;
    private string? _cachedBuildOrigin;
    private DateTimeOffset? _lastCompiledAt;
    private YaraRuleStoreState _storeState = new();

    public YaraEngineService(
        HttpClient http,
        ISettingsService settings,
        string? yaraExecutablePath = null,
        string? yaracExecutablePath = null,
        string? bundledRulesDirectory = null)
    {
        _http = http;
        _settings = settings;
        _explicitYaraPath = yaraExecutablePath;
        _explicitYaracPath = yaracExecutablePath;
        _explicitBundledRulesDir = bundledRulesDirectory;
    }

    public IReadOnlyList<YaraTrustedRepository> TrustedRepositories { get; } = new[]
    {
        new YaraTrustedRepository
        {
            Id = "neo23x0-signature-base",
            Name = "Neo23x0 / signature-base (Nextron Systems)",
            Description = "Trusted open-source YARA detection rules for webshells, ransomware indicators, exploit kits, and suspicious tools.",
            RepositoryUrl = "https://github.com/Neo23x0/signature-base",
            License = "Detection Rule License (DRL) 1.1 / Apache-2.0",
            RuleFileUrls = new[]
            {
                "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/gen_webshells.yar",
                "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/gen_powershell_susp.yar",
                "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/crime_ransomware_general.yar",
                "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/gen_loaders.yar"
            }
        },
        new YaraTrustedRepository
        {
            Id = "yara-rules-community",
            Name = "Yara-Rules / rules (Community Repository)",
            Description = "Community-maintained open-source YARA rule sets covering webshells, capabilities, and suspicious scripts.",
            RepositoryUrl = "https://github.com/Yara-Rules/rules",
            License = "GPL-2.0 / Community Open Source",
            RuleFileUrls = new[]
            {
                "https://raw.githubusercontent.com/Yara-Rules/rules/master/webshells/WShell_PHP_in_images.yar",
                "https://raw.githubusercontent.com/Yara-Rules/rules/master/webshells/WShell_ChinaChopper.yar",
                "https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/RANSOM_WannaCry.yar",
                "https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/RANSOM_Locky.yar"
            }
        }
    };

    private string YaraRootDir => Path.Combine(_settings.DataDirectory, "yara");
    private string BundledRulesStoreDir => Path.Combine(YaraRootDir, "rules", "bundled");
    private string UserRulesStoreDir => Path.Combine(YaraRootDir, "rules", "user");
    private string RepoRulesStoreDir => Path.Combine(YaraRootDir, "rules", "repository");
    private string CompiledDir => Path.Combine(YaraRootDir, "compiled");
    private string CompiledBundlePath => Path.Combine(CompiledDir, "active_rules.yarc");
    private string StoreStatePath => Path.Combine(YaraRootDir, "rules-state.json");

    internal string? FindYaraExecutable() => FindBinary(_explicitYaraPath, "yara64.exe", "yara.exe", "yara");
    internal string? FindYaracExecutable() => FindBinary(_explicitYaracPath, "yarac64.exe", "yarac.exe", "yarac");

    private string? FindBinary(string? explicitPath, params string[] names)
    {
        if (!string.IsNullOrWhiteSpace(explicitPath) && File.Exists(explicitPath))
            return explicitPath;

        var candidateDirs = new List<string>();
        var envNativeDir = Environment.GetEnvironmentVariable("BECETTI_YARA_NATIVE_DIR");
        if (!string.IsNullOrWhiteSpace(envNativeDir))
            candidateDirs.Add(envNativeDir);

        candidateDirs.AddRange(new[]
        {
            Path.Combine(AppContext.BaseDirectory, "Native", "yara", "win-x64"),
            Path.Combine(AppContext.BaseDirectory, "Native", "yara"),
            AppContext.BaseDirectory,
            Path.Combine(YaraRootDir, "bin")
        });

        // Also support running tests directly from repo tree
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        for (var i = 0; i < 6 && current is not null; i++)
        {
            var repoNative = Path.Combine(current.FullName, "src", "Becetti.Security.App", "Native", "yara", "win-x64");
            if (Directory.Exists(repoNative))
            {
                candidateDirs.Add(repoNative);
                break;
            }
            current = current.Parent;
        }

        foreach (var dir in candidateDirs)
        {
            foreach (var name in names)
            {
                var full = Path.Combine(dir, name);
                if (File.Exists(full))
                    return full;
            }
        }

        // Check PATH as a last resort
        var pathEnv = Environment.GetEnvironmentVariable("PATH");
        if (!string.IsNullOrWhiteSpace(pathEnv))
        {
            foreach (var segment in pathEnv.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
            {
                var trimmed = segment.Trim();
                foreach (var name in names)
                {
                    try
                    {
                        var full = Path.Combine(trimmed, name);
                        if (File.Exists(full))
                            return full;
                    }
                    catch
                    {
                        // Ignore malformed PATH segments
                    }
                }
            }
        }

        return null;
    }

    private string? FindBundledRulesSourceDirectory()
    {
        if (!string.IsNullOrWhiteSpace(_explicitBundledRulesDir) && Directory.Exists(_explicitBundledRulesDir))
            return _explicitBundledRulesDir;

        var direct = Path.Combine(AppContext.BaseDirectory, "Rules", "yara");
        if (Directory.Exists(direct))
            return direct;

        var current = new DirectoryInfo(AppContext.BaseDirectory);
        for (var i = 0; i < 6 && current is not null; i++)
        {
            var candidate = Path.Combine(current.FullName, "src", "Becetti.Security.App", "Rules", "yara");
            if (Directory.Exists(candidate))
                return candidate;
            current = current.Parent;
        }

        return null;
    }

    public async Task<OperationResult<YaraEngineInfo>> InitializeAsync(CancellationToken ct = default)
    {
        await _rulesLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            EnsureDirectories();
            LoadStoreStateUnlocked();
            SyncBundledRulesUnlocked();
            return await RebuildCompiledRulesUnlockedAsync(ct).ConfigureAwait(false);
        }
        finally
        {
            _rulesLock.Release();
        }
    }

    public async Task<OperationResult<YaraEngineInfo>> GetEngineInfoAsync(CancellationToken ct = default)
    {
        await _rulesLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            EnsureDirectories();
            LoadStoreStateUnlocked();
            SyncBundledRulesUnlocked();

            var info = await BuildEngineInfoUnlockedAsync(ct).ConfigureAwait(false);
            return info.IsAvailable
                ? OperationResult<YaraEngineInfo>.Ok(info, $"Native YARA engine {info.Version} is ready.")
                : OperationResult<YaraEngineInfo>.Fail(info.Error ?? "Native YARA binaries were not found.", "YARA_MISSING");
        }
        finally
        {
            _rulesLock.Release();
        }
    }

    public async Task<OperationResult<IReadOnlyList<YaraRuleFileInfo>>> GetRuleFilesAsync(CancellationToken ct = default)
    {
        await _rulesLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            EnsureDirectories();
            LoadStoreStateUnlocked();
            SyncBundledRulesUnlocked();
            var list = EnumerateRuleFilesUnlocked();
            return OperationResult<IReadOnlyList<YaraRuleFileInfo>>.Ok(list, $"Found {list.Count} YARA rule file(s).");
        }
        finally
        {
            _rulesLock.Release();
        }
    }

    public async Task<OperationResult<YaraRuleValidationResult>> ValidateRuleFileAsync(string ruleFilePath, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(ruleFilePath) || !File.Exists(ruleFilePath))
            return OperationResult<YaraRuleValidationResult>.Fail("Rule file does not exist.", "FILE_NOT_FOUND");

        if (!IsSupportedRuleExtension(ruleFilePath))
            return OperationResult<YaraRuleValidationResult>.Fail("Only .yar and .yara rule files are supported.", "INVALID_EXTENSION");

        var yarac = FindYaracExecutable();
        if (yarac is null)
            return OperationResult<YaraRuleValidationResult>.Fail("Native YARA compiler (yarac64.exe) was not found.", "YARA_MISSING");

        var result = await CompileSingleRuleForValidationAsync(yarac, ruleFilePath, ct).ConfigureAwait(false);
        return result.IsValid
            ? OperationResult<YaraRuleValidationResult>.Ok(result, $"Rule file validated cleanly ({result.RuleCount} rule(s)).")
            : OperationResult<YaraRuleValidationResult>.Fail(result.ErrorMessage ?? "YARA rule compilation failed.", "INVALID_RULE");
    }

    public async Task<OperationResult<YaraRuleFileInfo>> ImportRuleFileAsync(string sourceFilePath, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(sourceFilePath) || !File.Exists(sourceFilePath))
            return OperationResult<YaraRuleFileInfo>.Fail("Selected rule file was not found.", "FILE_NOT_FOUND");

        if (!IsSupportedRuleExtension(sourceFilePath))
            return OperationResult<YaraRuleFileInfo>.Fail("Only .yar and .yara files can be imported.", "INVALID_EXTENSION");

        // Validate BEFORE loading into the active rules directory (Req 10 & 11)
        var validation = await ValidateRuleFileAsync(sourceFilePath, ct).ConfigureAwait(false);
        if (!validation.Success || validation.Value is null || !validation.Value.IsValid)
        {
            return OperationResult<YaraRuleFileInfo>.Fail(
                $"Rule rejected before loading — invalid YARA syntax or unsupported module: {validation.Message}",
                "INVALID_RULE");
        }

        await _rulesLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            EnsureDirectories();
            LoadStoreStateUnlocked();

            var safeFileName = SanitizeRuleFileName(Path.GetFileName(sourceFilePath));
            var destPath = Path.Combine(UserRulesStoreDir, safeFileName);
            File.Copy(sourceFilePath, destPath, overwrite: true);

            var ruleId = MakeRuleId(YaraRuleSource.User, safeFileName);
            _storeState.DisabledRuleIds.Remove(ruleId);
            _storeState.ValidationCache[ruleId] = new CachedRuleValidation
            {
                Sha256 = ComputeFileSha256(destPath),
                IsValid = true,
                RuleNames = validation.Value.RuleNames.ToList(),
                LastValidatedAt = DateTimeOffset.UtcNow
            };
            SaveStoreStateUnlocked();

            await RebuildCompiledRulesUnlockedAsync(ct).ConfigureAwait(false);

            var imported = EnumerateRuleFilesUnlocked().FirstOrDefault(r => r.Id == ruleId);
            if (imported is null)
                return OperationResult<YaraRuleFileInfo>.Fail("Rule was copied but could not be indexed.", "IMPORT_ERROR");

            return OperationResult<YaraRuleFileInfo>.Ok(
                imported,
                $"Validated and imported '{imported.FileName}' ({imported.RuleCount} rule(s)).");
        }
        finally
        {
            _rulesLock.Release();
        }
    }

    public async Task<OperationResult<YaraEngineInfo>> SetRuleEnabledAsync(string ruleId, bool enabled, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(ruleId))
            return OperationResult<YaraEngineInfo>.Fail("Rule identifier is required.", "INVALID_ARGUMENT");

        await _rulesLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            EnsureDirectories();
            LoadStoreStateUnlocked();

            if (enabled)
                _storeState.DisabledRuleIds.Remove(ruleId);
            else
                _storeState.DisabledRuleIds.Add(ruleId);

            SaveStoreStateUnlocked();
            return await RebuildCompiledRulesUnlockedAsync(ct).ConfigureAwait(false);
        }
        finally
        {
            _rulesLock.Release();
        }
    }

    public async Task<OperationResult<YaraEngineInfo>> RemoveRuleFileAsync(string ruleId, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(ruleId))
            return OperationResult<YaraEngineInfo>.Fail("Rule identifier is required.", "INVALID_ARGUMENT");

        await _rulesLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            EnsureDirectories();
            LoadStoreStateUnlocked();

            var target = EnumerateRuleFilesUnlocked().FirstOrDefault(r => r.Id == ruleId);
            if (target is null)
                return OperationResult<YaraEngineInfo>.Fail("Rule file was not found.", "FILE_NOT_FOUND");

            if (!target.CanDelete)
                return OperationResult<YaraEngineInfo>.Fail("Bundled baseline rules cannot be deleted; disable them instead.", "BUNDLED_PROTECTED");

            if (File.Exists(target.FullPath))
                File.Delete(target.FullPath);

            _storeState.DisabledRuleIds.Remove(ruleId);
            _storeState.ValidationCache.Remove(ruleId);
            SaveStoreStateUnlocked();

            return await RebuildCompiledRulesUnlockedAsync(ct).ConfigureAwait(false);
        }
        finally
        {
            _rulesLock.Release();
        }
    }

    public async Task<OperationResult<YaraEngineInfo>> RebuildCompiledRulesAsync(CancellationToken ct = default)
    {
        await _rulesLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            EnsureDirectories();
            LoadStoreStateUnlocked();
            SyncBundledRulesUnlocked();
            return await RebuildCompiledRulesUnlockedAsync(ct).ConfigureAwait(false);
        }
        finally
        {
            _rulesLock.Release();
        }
    }

    public Task<OperationResult<YaraScanReport>> ScanAsync(
        string targetPath,
        IProgress<YaraScanProgress>? progress = null,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(targetPath))
            return Task.FromResult(OperationResult<YaraScanReport>.Fail("A file or folder path is required.", "INVALID_TARGET"));

        return ScanTargetsAsync(new[] { targetPath }, targetPath, progress, ct);
    }

    public async Task<OperationResult<YaraScanReport>> ScanTargetsAsync(
        IReadOnlyList<string> targetPaths,
        string displayLabel,
        IProgress<YaraScanProgress>? progress = null,
        CancellationToken ct = default)
    {
        if (targetPaths.Count == 0)
            return OperationResult<YaraScanReport>.Fail("At least one file or folder path is required.", "INVALID_TARGET");

        var yara = FindYaraExecutable();
        if (yara is null)
            return OperationResult<YaraScanReport>.Fail(
                "Native YARA engine (yara64.exe) was not found. Build or install the Windows x64 YARA binaries.",
                "YARA_MISSING");

        // Ensure rules are initialized and compiled
        YaraEngineInfo engineInfo;
        await _rulesLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            EnsureDirectories();
            LoadStoreStateUnlocked();
            SyncBundledRulesUnlocked();

            if (!File.Exists(CompiledBundlePath))
            {
                var build = await RebuildCompiledRulesUnlockedAsync(ct).ConfigureAwait(false);
                if (!build.Success || build.Value is null)
                    return OperationResult<YaraScanReport>.Fail(build.Message, build.ErrorCode);
                engineInfo = build.Value;
            }
            else
            {
                engineInfo = await BuildEngineInfoUnlockedAsync(ct).ConfigureAwait(false);
                if (engineInfo.ValidRuleFiles == 0)
                {
                    var build = await RebuildCompiledRulesUnlockedAsync(ct).ConfigureAwait(false);
                    if (!build.Success || build.Value is null)
                        return OperationResult<YaraScanReport>.Fail(build.Message, build.ErrorCode);
                    engineInfo = build.Value;
                }
            }
        }
        finally
        {
            _rulesLock.Release();
        }

        if (!engineInfo.CompiledBundleReady || engineInfo.ActiveRuleCount == 0)
        {
            return OperationResult<YaraScanReport>.Fail(
                "No valid compiled YARA rules are active. Enable or import at least one valid .yar/.yara rule file.",
                "NO_ACTIVE_RULES");
        }

        var startedAt = DateTimeOffset.UtcNow;
        var stopwatch = Stopwatch.StartNew();
        var errors = new List<YaraScanError>();
        var filesToScan = new List<string>();
        var filesSkipped = 0;

        foreach (var rawTarget in targetPaths)
        {
            if (string.IsNullOrWhiteSpace(rawTarget))
                continue;

            var target = rawTarget.Trim();
            if (File.Exists(target))
            {
                filesToScan.Add(target);
            }
            else if (Directory.Exists(target))
            {
                EnumerateFilesSafely(target, filesToScan, errors, ref filesSkipped, ct);
            }
            else
            {
                errors.Add(new YaraScanError
                {
                    FilePath = target,
                    Code = "NOT_FOUND",
                    Message = "Target path does not exist."
                });
            }
        }

        if (filesToScan.Count == 0 && errors.Count > 0)
        {
            return OperationResult<YaraScanReport>.Fail(
                $"No scannable files were found at '{displayLabel}'. {errors[0].Message}",
                "NO_SCANNABLE_FILES");
        }

        var matches = new List<YaraRuleMatch>();
        var filesScanned = 0;
        var wasCancelled = false;

        progress?.Report(new YaraScanProgress
        {
            FilesScanned = 0,
            TotalFiles = filesToScan.Count,
            MatchesFound = 0,
            ErrorsCount = errors.Count,
            CurrentFile = filesToScan.FirstOrDefault() ?? string.Empty,
            Elapsed = stopwatch.Elapsed
        });

        foreach (var file in filesToScan)
        {
            if (ct.IsCancellationRequested)
            {
                wasCancelled = true;
                break;
            }

            try
            {
                var fi = new FileInfo(file);
                if (fi.Length > MaxScanFileBytes)
                {
                    filesSkipped++;
                    errors.Add(new YaraScanError
                    {
                        FilePath = file,
                        Code = "FILE_TOO_LARGE",
                        Message = $"Skipped file larger than {MaxScanFileBytes / (1024 * 1024)} MB ({fi.Length / (1024 * 1024)} MB)."
                    });
                    filesScanned++;
                    progress?.Report(new YaraScanProgress
                    {
                        FilesScanned = filesScanned,
                        TotalFiles = filesToScan.Count,
                        MatchesFound = matches.Count,
                        ErrorsCount = errors.Count,
                        CurrentFile = file,
                        Elapsed = stopwatch.Elapsed
                    });
                    continue;
                }
            }
            catch (Exception ex)
            {
                filesSkipped++;
                errors.Add(new YaraScanError
                {
                    FilePath = file,
                    Code = "ACCESS_ERROR",
                    Message = ex.Message
                });
                filesScanned++;
                continue;
            }

            progress?.Report(new YaraScanProgress
            {
                FilesScanned = filesScanned,
                TotalFiles = filesToScan.Count,
                MatchesFound = matches.Count,
                ErrorsCount = errors.Count,
                CurrentFile = file,
                Elapsed = stopwatch.Elapsed
            });

            var run = await RunProcessAsync(
                yara,
                new[] { "-C", "-m", "-s", "-g", "-w", "-a", "25", CompiledBundlePath, file },
                SingleFileScanTimeout,
                ct).ConfigureAwait(false);

            if (ct.IsCancellationRequested)
            {
                wasCancelled = true;
                break;
            }

            filesScanned++;

            if (!run.Success || run.Value is null)
            {
                errors.Add(new YaraScanError
                {
                    FilePath = file,
                    Code = run.ErrorCode ?? "SCAN_ERROR",
                    Message = run.Message
                });
            }
            else if (run.Value.ExitCode != 0)
            {
                var errDetail = string.IsNullOrWhiteSpace(run.Value.Error)
                    ? $"yara64 exited with code {run.Value.ExitCode}"
                    : run.Value.Error.Trim();
                errors.Add(new YaraScanError
                {
                    FilePath = file,
                    Code = "YARA_EXIT_" + run.Value.ExitCode,
                    Message = errDetail
                });
            }
            else if (!string.IsNullOrWhiteSpace(run.Value.Output))
            {
                var parsed = ParseYaraScanOutput(run.Value.Output, file);
                matches.AddRange(parsed);
            }

            progress?.Report(new YaraScanProgress
            {
                FilesScanned = filesScanned,
                TotalFiles = filesToScan.Count,
                MatchesFound = matches.Count,
                ErrorsCount = errors.Count,
                CurrentFile = file,
                Elapsed = stopwatch.Elapsed
            });
        }

        var report = new YaraScanReport
        {
            TargetPath = displayLabel,
            StartedAt = startedAt,
            EndedAt = DateTimeOffset.UtcNow,
            EngineVersion = engineInfo.Version ?? "unknown",
            ActiveRuleFilesCount = engineInfo.ValidRuleFiles,
            TotalRulesLoaded = engineInfo.ActiveRuleCount,
            FilesScanned = filesScanned,
            FilesSkipped = filesSkipped,
            WasCancelled = wasCancelled,
            Matches = matches,
            Errors = errors
        };

        var summary = wasCancelled
            ? $"YARA scan cancelled after {report.FilesScanned} file(s); {report.Matches.Count} match(es) found."
            : report.ThreatFound
                ? $"YARA detected {report.Matches.Count} rule match(es) across {report.FilesScanned} scanned file(s)."
                : $"YARA scan completed cleanly: 0 matches across {report.FilesScanned} file(s) ({report.TotalRulesLoaded} rules).";

        return OperationResult<YaraScanReport>.Ok(report, summary);
    }

    public async Task<OperationResult<YaraRuleUpdateResult>> UpdateRulesFromRepositoryAsync(
        string repositoryId,
        CancellationToken ct = default)
    {
        var repo = TrustedRepositories.FirstOrDefault(r =>
            string.Equals(r.Id, repositoryId, StringComparison.OrdinalIgnoreCase));
        if (repo is null)
            return OperationResult<YaraRuleUpdateResult>.Fail($"Unknown trusted repository '{repositoryId}'.", "UNKNOWN_REPO");

        return await DownloadAndValidateRulesAsync(repo.Name, repo.Id, repo.RuleFileUrls, ct).ConfigureAwait(false);
    }

    public async Task<OperationResult<YaraRuleUpdateResult>> UpdateRuleFromHttpsUrlAsync(
        string ruleUrl,
        CancellationToken ct = default)
    {
        if (!Uri.TryCreate(ruleUrl?.Trim(), UriKind.Absolute, out var uri) ||
            !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            return OperationResult<YaraRuleUpdateResult>.Fail(
                "Only HTTPS URLs are allowed when downloading remote YARA rules.",
                "INVALID_URL");
        }

        if (!IsSupportedRuleExtension(uri.AbsolutePath))
        {
            return OperationResult<YaraRuleUpdateResult>.Fail(
                "Remote rule URL must point directly to a .yar or .yara file.",
                "INVALID_EXTENSION");
        }

        return await DownloadAndValidateRulesAsync(uri.Host, "custom", new[] { uri.ToString() }, ct).ConfigureAwait(false);
    }

    private async Task<OperationResult<YaraRuleUpdateResult>> DownloadAndValidateRulesAsync(
        string sourceName,
        string prefix,
        IReadOnlyList<string> urls,
        CancellationToken ct)
    {
        var yarac = FindYaracExecutable();
        if (yarac is null)
            return OperationResult<YaraRuleUpdateResult>.Fail("Native YARA compiler (yarac64.exe) was not found.", "YARA_MISSING");

        var importedFiles = new List<string>();
        var rejectedFiles = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var stagingDir = Path.Combine(Path.GetTempPath(), "becetti-yara-update-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(stagingDir);

        try
        {
            var stagedValid = new List<(string FileName, string StagingPath, YaraRuleValidationResult Validation)>();

            foreach (var url in urls)
            {
                ct.ThrowIfCancellationRequested();
                var rawName = Path.GetFileName(new Uri(url).AbsolutePath);
                var safeName = SanitizeRuleFileName($"{prefix}_{rawName}");
                var stagingPath = Path.Combine(stagingDir, safeName);

                try
                {
                    using var req = new HttpRequestMessage(HttpMethod.Get, url);
                    req.Headers.UserAgent.ParseAdd("BECETTI-SECURITY/1.0");
                    using var resp = await _http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);

                    if (!resp.IsSuccessStatusCode)
                    {
                        rejectedFiles[safeName] = $"Download failed: HTTP {(int)resp.StatusCode} {resp.StatusCode}";
                        continue;
                    }

                    if (resp.Content.Headers.ContentLength is > MaxRuleFileDownloadBytes)
                    {
                        rejectedFiles[safeName] = $"Rejected: file exceeds {MaxRuleFileDownloadBytes / (1024 * 1024)} MB safety limit.";
                        continue;
                    }

                    await using var stream = await resp.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
                    using var ms = new MemoryStream();
                    var buffer = new byte[16384];
                    int read;
                    while ((read = await stream.ReadAsync(buffer, ct).ConfigureAwait(false)) > 0)
                    {
                        ms.Write(buffer, 0, read);
                        if (ms.Length > MaxRuleFileDownloadBytes)
                            throw new InvalidOperationException("Rule file exceeded maximum allowed download size.");
                    }

                    await File.WriteAllBytesAsync(stagingPath, ms.ToArray(), ct).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    rejectedFiles[safeName] = $"Download error: {ex.Message}";
                    continue;
                }

                // Validate EVERY downloaded rule individually with yarac64.exe BEFORE touching active rules
                var validation = await CompileSingleRuleForValidationAsync(yarac, stagingPath, ct).ConfigureAwait(false);
                if (!validation.IsValid)
                {
                    rejectedFiles[safeName] = validation.ErrorMessage ?? "Failed yarac64 compilation.";
                    continue;
                }

                stagedValid.Add((safeName, stagingPath, validation));
            }

            if (stagedValid.Count > 0)
            {
                await _rulesLock.WaitAsync(ct).ConfigureAwait(false);
                try
                {
                    EnsureDirectories();
                    LoadStoreStateUnlocked();

                    foreach (var (fileName, stagingPath, validation) in stagedValid)
                    {
                        var destPath = Path.Combine(RepoRulesStoreDir, fileName);
                        File.Copy(stagingPath, destPath, overwrite: true);
                        var ruleId = MakeRuleId(YaraRuleSource.Repository, fileName);
                        _storeState.DisabledRuleIds.Remove(ruleId);
                        _storeState.ValidationCache[ruleId] = new CachedRuleValidation
                        {
                            Sha256 = ComputeFileSha256(destPath),
                            IsValid = true,
                            RuleNames = validation.RuleNames.ToList(),
                            LastValidatedAt = DateTimeOffset.UtcNow
                        };
                        importedFiles.Add(fileName);
                    }

                    SaveStoreStateUnlocked();
                    await RebuildCompiledRulesUnlockedAsync(ct).ConfigureAwait(false);
                }
                finally
                {
                    _rulesLock.Release();
                }
            }

            var updateResult = new YaraRuleUpdateResult
            {
                SourceName = sourceName,
                AttemptedCount = urls.Count,
                ValidatedAndImportedCount = importedFiles.Count,
                RejectedCount = rejectedFiles.Count,
                ImportedFiles = importedFiles,
                RejectedFiles = rejectedFiles,
                CompletedAt = DateTimeOffset.UtcNow
            };

            if (importedFiles.Count == 0 && rejectedFiles.Count > 0)
            {
                var firstErr = rejectedFiles.First();
                return OperationResult<YaraRuleUpdateResult>.Fail(
                    $"No rules from {sourceName} passed validation ({rejectedFiles.Count} rejected; e.g. {firstErr.Key}: {firstErr.Value}). Existing active rules were left untouched.",
                    "UPDATE_REJECTED");
            }

            return OperationResult<YaraRuleUpdateResult>.Ok(
                updateResult,
                $"Updated rules from {sourceName}: {importedFiles.Count} validated & active, {rejectedFiles.Count} rejected safely.");
        }
        finally
        {
            try
            {
                if (Directory.Exists(stagingDir))
                    Directory.Delete(stagingDir, recursive: true);
            }
            catch
            {
                // Cleanup is best-effort
            }
        }
    }

    public async Task<OperationResult<YaraProcessScanReport>> ScanProcessAsync(int processId, CancellationToken ct = default)
    {
        if (processId <= 4)
            return OperationResult<YaraProcessScanReport>.Fail("Cannot scan kernel/idle system PID.", "INVALID_PID");

        var startedAt = DateTimeOffset.UtcNow;
        var init = await EnsureReadyForScanAsync(ct).ConfigureAwait(false);
        if (!init.Success || init.Value is null)
            return OperationResult<YaraProcessScanReport>.Fail(init.Message, init.ErrorCode);

        var yaraExe = init.Value.YaraExecutablePath!;
        string procName = $"PID-{processId}";
        string? exePath = null;
        try
        {
            using var proc = Process.GetProcessById(processId);
            procName = proc.ProcessName;
            try { exePath = proc.MainModule?.FileName; } catch { }
        }
        catch (Exception ex)
        {
            return OperationResult<YaraProcessScanReport>.Fail($"Process {processId} is not running or inaccessible: {ex.Message}", "PROCESS_NOT_FOUND");
        }

        var args = new[] { "-C", "-g", "-m", "-s", "-t", "30", CompiledBundlePath, processId.ToString() };
        var exec = await RunProcessAsync(yaraExe, args, TimeSpan.FromSeconds(35), ct).ConfigureAwait(false);

        var matches = new List<YaraProcessMatch>();
        var notes = new List<string>();
        int scanned = 0;
        int skippedDenied = 0;

        if (exec.ExitCode == 0)
        {
            scanned = 1;
            var parsed = ParseYaraScanOutput(exec.StdOut, processId.ToString());
            foreach (var m in parsed)
            {
                matches.Add(new YaraProcessMatch
                {
                    ProcessId = processId,
                    ProcessName = procName,
                    ExecutablePath = exePath,
                    RuleName = m.RuleName,
                    Description = m.Description,
                    Severity = m.Severity,
                    Tags = m.Tags
                });
            }
        }
        else
        {
            skippedDenied = 1;
            notes.Add($"PID {processId} ({procName}): {FormatProcessFailure(exec)}");
        }

        var report = new YaraProcessScanReport
        {
            StartedAt = startedAt,
            EndedAt = DateTimeOffset.UtcNow,
            ProcessesEnumerated = 1,
            ProcessesScanned = scanned,
            ProcessesSkippedAccessDenied = skippedDenied,
            Matches = matches,
            Notes = notes
        };

        return OperationResult<YaraProcessScanReport>.Ok(
            report,
            matches.Count > 0
                ? $"Memory scan detected {matches.Count} YARA match(es) in {procName} (PID {processId})."
                : scanned == 1
                    ? $"Process {procName} (PID {processId}) scanned cleanly in memory."
                    : $"Process {procName} (PID {processId}) could not be opened for memory reading (protected/elevated).");
    }

    public async Task<OperationResult<YaraProcessScanReport>> ScanRunningProcessesAsync(
        IProgress<YaraScanProgress>? progress = null,
        CancellationToken ct = default)
    {
        var startedAt = DateTimeOffset.UtcNow;
        var init = await EnsureReadyForScanAsync(ct).ConfigureAwait(false);
        if (!init.Success || init.Value is null)
            return OperationResult<YaraProcessScanReport>.Fail(init.Message, init.ErrorCode);

        var yaraExe = init.Value.YaraExecutablePath!;
        var selfPid = Environment.ProcessId;
        var allProcs = Process.GetProcesses()
            .Where(p => p.Id > 4 && p.Id != selfPid)
            .OrderBy(p => p.ProcessName, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var matches = new List<YaraProcessMatch>();
        var notes = new List<string>();
        int scanned = 0;
        int skipped = 0;
        bool cancelled = false;
        int total = allProcs.Count;

        try
        {
            for (int i = 0; i < allProcs.Count; i++)
            {
                if (ct.IsCancellationRequested)
                {
                    cancelled = true;
                    break;
                }

                var proc = allProcs[i];
                int pid = proc.Id;
                string name = proc.ProcessName;
                string? exePath = null;
                try { exePath = proc.MainModule?.FileName; } catch { }

                progress?.Report(new YaraScanProgress
                {
                    FilesScanned = i,
                    TotalFiles = total,
                    MatchesFound = matches.Count,
                    ErrorsCount = skipped,
                    CurrentFile = $"PID {pid} ({name})",
                    Elapsed = DateTimeOffset.UtcNow - startedAt
                });

                var args = new[] { "-C", "-g", "-m", "-s", "-t", "15", CompiledBundlePath, pid.ToString() };
                var exec = await RunProcessAsync(yaraExe, args, TimeSpan.FromSeconds(20), ct).ConfigureAwait(false);

                if (exec.ExitCode == 0)
                {
                    scanned++;
                    var parsed = ParseYaraScanOutput(exec.StdOut, pid.ToString());
                    foreach (var m in parsed)
                    {
                        matches.Add(new YaraProcessMatch
                        {
                            ProcessId = pid,
                            ProcessName = name,
                            ExecutablePath = exePath,
                            RuleName = m.RuleName,
                            Description = m.Description,
                            Severity = m.Severity,
                            Tags = m.Tags
                        });
                    }
                }
                else
                {
                    skipped++;
                    if (notes.Count < 40)
                        notes.Add($"Skipped PID {pid} ({name}): {FormatProcessFailure(exec)}");
                }
            }
        }
        finally
        {
            foreach (var p in allProcs)
            {
                try { p.Dispose(); } catch { }
            }
        }

        progress?.Report(new YaraScanProgress
        {
            FilesScanned = total,
            TotalFiles = total,
            MatchesFound = matches.Count,
            ErrorsCount = skipped,
            CurrentFile = cancelled ? "Cancelled" : "Complete",
            Elapsed = DateTimeOffset.UtcNow - startedAt
        });

        var report = new YaraProcessScanReport
        {
            StartedAt = startedAt,
            EndedAt = DateTimeOffset.UtcNow,
            ProcessesEnumerated = total,
            ProcessesScanned = scanned,
            ProcessesSkippedAccessDenied = skipped,
            WasCancelled = cancelled,
            Matches = matches,
            Notes = notes
        };

        return OperationResult<YaraProcessScanReport>.Ok(
            report,
            matches.Count > 0
                ? $"Memory scan found {matches.Count} YARA match(es) across {scanned} scanned process(es)."
                : $"Scanned {scanned} process(es) in memory — no YARA matches ({skipped} protected/inaccessible skipped).");
    }

    public string FormatReportAsText(YaraScanReport report)
    {
        var sb = new StringBuilder();
        sb.AppendLine("========================================================================");
        sb.AppendLine("BECETTI SECURITY — Native YARA Engine Scan Report");
        sb.AppendLine("========================================================================");
        sb.AppendLine($"Scan ID:             {report.ScanId}");
        sb.AppendLine($"Target:              {report.TargetPath}");
        sb.AppendLine($"Engine:              YARA {report.EngineVersion} (Local Native Engine)");
        sb.AppendLine($"Started (UTC):       {report.StartedAt:u}");
        sb.AppendLine($"Ended (UTC):         {report.EndedAt:u}");
        sb.AppendLine($"Duration:            {report.Duration.TotalSeconds:F2}s");
        sb.AppendLine($"Active Rule Files:   {report.ActiveRuleFilesCount}");
        sb.AppendLine($"Loaded Rules:        {report.TotalRulesLoaded}");
        sb.AppendLine($"Files Scanned:       {report.FilesScanned}");
        sb.AppendLine($"Files Skipped:       {report.FilesSkipped}");
        sb.AppendLine($"Cancelled:           {(report.WasCancelled ? "Yes" : "No")}");
        sb.AppendLine($"Verdict:             {(report.ThreatFound ? $"DETECTIONS FOUND ({report.Matches.Count})" : "CLEAN (0 matches)")}");
        sb.AppendLine();

        if (report.Matches.Count > 0)
        {
            sb.AppendLine("--- MATCHED YARA RULES ---");
            foreach (var match in report.Matches)
            {
                sb.AppendLine($"Rule:        {match.RuleName}");
                sb.AppendLine($"File:        {match.FilePath}");
                sb.AppendLine($"Severity:    {match.Severity} | Category: {match.Category}");
                if (!string.IsNullOrWhiteSpace(match.Description))
                    sb.AppendLine($"Description: {match.Description}");
                if (!string.IsNullOrWhiteSpace(match.Author))
                    sb.AppendLine($"Author:      {match.Author}");
                if (!string.IsNullOrWhiteSpace(match.Reference))
                    sb.AppendLine($"Reference:   {match.Reference}");
                if (match.Tags.Count > 0)
                    sb.AppendLine($"Tags:        {match.TagsText}");
                if (match.MatchedStrings.Count > 0)
                {
                    sb.AppendLine("Indicators:");
                    foreach (var s in match.MatchedStrings.Take(12))
                        sb.AppendLine($"  - {s.DisplayLine}");
                }
                sb.AppendLine();
            }
        }
        else
        {
            sb.AppendLine("No YARA rules matched any scanned files.");
            sb.AppendLine();
        }

        if (report.Errors.Count > 0)
        {
            sb.AppendLine("--- SCAN ERRORS / SKIPPED FILES ---");
            foreach (var err in report.Errors)
                sb.AppendLine($"  * {err.DisplayLine}");
            sb.AppendLine();
        }

        sb.AppendLine("------------------------------------------------------------------------");
        sb.AppendLine("YARA License Notice: Copyright (c) 2007-2016 The YARA Authors.");
        sb.AppendLine("Official source: https://github.com/VirusTotal/yara (BSD 3-Clause).");
        return sb.ToString();
    }

    public string FormatReportAsJson(YaraScanReport report) =>
        JsonSerializer.Serialize(report, JsonOptions);

    public byte[] FormatReportAsPdf(YaraScanReport report)
    {
        var text = FormatReportAsText(report);
        var lines = new List<string>();
        foreach (var rawLine in text.Replace("\r\n", "\n").Split('\n'))
        {
            if (rawLine.Length <= 88)
            {
                lines.Add(rawLine);
                continue;
            }
            for (var i = 0; i < rawLine.Length; i += 88)
                lines.Add(rawLine.Substring(i, Math.Min(88, rawLine.Length - i)));
        }

        return SimplePdfWriter.Write("BECETTI SECURITY — Native YARA Scan Report", lines);
    }

    // ---------- Internal compilation, validation & parsing ----------

    private async Task<OperationResult<YaraEngineInfo>> RebuildCompiledRulesUnlockedAsync(CancellationToken ct)
    {
        var yarac = FindYaracExecutable();
        if (yarac is null)
        {
            var missingInfo = await BuildEngineInfoUnlockedAsync(ct).ConfigureAwait(false);
            return OperationResult<YaraEngineInfo>.Fail(
                missingInfo.Error ?? "Native YARA compiler (yarac64.exe) was not found.",
                "YARA_MISSING");
        }

        var files = EnumerateRuleFilesUnlocked();
        var validEnabled = new List<YaraRuleFileInfo>();

        // Step 1: Validate every enabled rule file individually so one bad/outdated rule NEVER breaks the scanner
        foreach (var rf in files)
        {
            if (!rf.IsEnabled)
                continue;

            var cached = _storeState.ValidationCache.TryGetValue(rf.Id, out var c) ? c : null;
            if (cached is not null && string.Equals(cached.Sha256, rf.Sha256, StringComparison.OrdinalIgnoreCase))
            {
                if (cached.IsValid)
                    validEnabled.Add(rf);
                continue;
            }

            var v = await CompileSingleRuleForValidationAsync(yarac, rf.FullPath, ct).ConfigureAwait(false);
            _storeState.ValidationCache[rf.Id] = new CachedRuleValidation
            {
                Sha256 = rf.Sha256,
                IsValid = v.IsValid,
                RuleNames = v.RuleNames.ToList(),
                ErrorMessage = v.ErrorMessage,
                LastValidatedAt = DateTimeOffset.UtcNow
            };

            if (v.IsValid)
                validEnabled.Add(rf);
        }

        SaveStoreStateUnlocked();

        // Step 2: Compile all valid enabled files together with unique namespaces into active_rules.yarc
        if (validEnabled.Count == 0)
        {
            if (File.Exists(CompiledBundlePath))
                File.Delete(CompiledBundlePath);

            var emptyInfo = await BuildEngineInfoUnlockedAsync(ct).ConfigureAwait(false);
            return OperationResult<YaraEngineInfo>.Ok(emptyInfo, "No enabled valid YARA rule files to compile.");
        }

        var tempOut = Path.Combine(CompiledDir, $"active_rules_{Guid.NewGuid():N}.yarc");
        try
        {
            var args = new List<string>();
            for (var i = 0; i < validEnabled.Count; i++)
            {
                var ns = $"ns_{i:D4}";
                args.Add($"{ns}:{validEnabled[i].FullPath}");
            }
            args.Add(tempOut);

            var run = await RunProcessAsync(yarac, args, CompileTimeout, ct).ConfigureAwait(false);
            if (!run.Success || run.Value is null || run.Value.ExitCode != 0 || !File.Exists(tempOut))
            {
                var err = !run.Success ? run.Message : (run.Value?.Error ?? run.Value?.Output ?? "yarac64 failed");
                return OperationResult<YaraEngineInfo>.Fail($"Failed to compile active YARA rules bundle: {err.Trim()}", "COMPILE_FAILED");
            }

            File.Move(tempOut, CompiledBundlePath, overwrite: true);
            _lastCompiledAt = DateTimeOffset.UtcNow;
        }
        finally
        {
            try
            {
                if (File.Exists(tempOut))
                    File.Delete(tempOut);
            }
            catch
            {
                // Best-effort cleanup
            }
        }

        var info = await BuildEngineInfoUnlockedAsync(ct).ConfigureAwait(false);
        return OperationResult<YaraEngineInfo>.Ok(
            info,
            $"Compiled {info.ValidRuleFiles} valid YARA rule file(s) ({info.ActiveRuleCount} rule(s)); {info.InvalidRuleFiles} invalid file(s) isolated.");
    }

    private async Task<YaraRuleValidationResult> CompileSingleRuleForValidationAsync(
        string yaracPath,
        string ruleFilePath,
        CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        var ruleNames = ExtractRuleNamesFromSource(ruleFilePath);
        var tempYarc = Path.Combine(Path.GetTempPath(), $"becetti-validate-{Guid.NewGuid():N}.yarc");

        try
        {
            var run = await RunProcessAsync(yaracPath, new[] { ruleFilePath, tempYarc }, CompileTimeout, ct).ConfigureAwait(false);
            sw.Stop();

            if (!run.Success || run.Value is null)
            {
                return new YaraRuleValidationResult
                {
                    FilePath = ruleFilePath,
                    IsValid = false,
                    RuleCount = ruleNames.Count,
                    RuleNames = ruleNames,
                    ErrorMessage = run.Message,
                    Duration = sw.Elapsed
                };
            }

            var warnings = SplitNonEmptyLines(run.Value.Error)
                .Where(l => l.Contains("warning:", StringComparison.OrdinalIgnoreCase))
                .ToList();

            if (run.Value.ExitCode != 0)
            {
                var err = string.IsNullOrWhiteSpace(run.Value.Error)
                    ? (string.IsNullOrWhiteSpace(run.Value.Output) ? $"yarac64 exited with code {run.Value.ExitCode}" : run.Value.Output.Trim())
                    : run.Value.Error.Trim();

                return new YaraRuleValidationResult
                {
                    FilePath = ruleFilePath,
                    IsValid = false,
                    RuleCount = ruleNames.Count,
                    RuleNames = ruleNames,
                    Warnings = warnings,
                    ErrorMessage = err,
                    Duration = sw.Elapsed
                };
            }

            if (ruleNames.Count == 0)
            {
                return new YaraRuleValidationResult
                {
                    FilePath = ruleFilePath,
                    IsValid = false,
                    RuleCount = 0,
                    RuleNames = Array.Empty<string>(),
                    Warnings = warnings,
                    ErrorMessage = "File contains no YARA rule declarations.",
                    Duration = sw.Elapsed
                };
            }

            return new YaraRuleValidationResult
            {
                FilePath = ruleFilePath,
                IsValid = true,
                RuleCount = ruleNames.Count,
                RuleNames = ruleNames,
                Warnings = warnings,
                Duration = sw.Elapsed
            };
        }
        finally
        {
            try
            {
                if (File.Exists(tempYarc))
                    File.Delete(tempYarc);
            }
            catch
            {
                // Ignore temp cleanup failure
            }
        }
    }

    private async Task<YaraEngineInfo> BuildEngineInfoUnlockedAsync(CancellationToken ct)
    {
        var yara = FindYaraExecutable();
        var yarac = FindYaracExecutable();
        var files = EnumerateRuleFilesUnlocked();

        var validFiles = files.Where(f => f.IsEnabled && f.Status == YaraRuleValidationStatus.Valid).ToList();
        var invalidFiles = files.Where(f => f.IsEnabled && f.Status == YaraRuleValidationStatus.Invalid).ToList();
        var disabledFiles = files.Where(f => !f.IsEnabled).ToList();

        if (yara is null || yarac is null)
        {
            return new YaraEngineInfo
            {
                IsAvailable = false,
                YaraExecutablePath = yara,
                YaracExecutablePath = yarac,
                Error = "Official YARA Windows x64 binaries (yara64.exe / yarac64.exe) were not found in Native\\yara\\win-x64. Run scripts/build-yara-win64.ps1 to build them.",
                TotalRuleFiles = files.Count,
                ValidRuleFiles = validFiles.Count,
                InvalidRuleFiles = invalidFiles.Count,
                DisabledRuleFiles = disabledFiles.Count,
                ActiveRuleCount = validFiles.Sum(f => f.RuleCount),
                CompiledBundleReady = File.Exists(CompiledBundlePath),
                LastCompiledAt = _lastCompiledAt
            };
        }

        if (_cachedVersion is null)
        {
            var verRun = await RunProcessAsync(yara, new[] { "--version" }, VersionTimeout, ct).ConfigureAwait(false);
            if (!verRun.Success || verRun.Value is null || verRun.Value.ExitCode != 0)
            {
                return new YaraEngineInfo
                {
                    IsAvailable = false,
                    YaraExecutablePath = yara,
                    YaracExecutablePath = yarac,
                    Error = $"yara64.exe failed to run: {(verRun.Success ? verRun.Value?.Error : verRun.Message)}",
                    TotalRuleFiles = files.Count
                };
            }

            _cachedVersion = verRun.Value.Output.Trim();
            _cachedBuildOrigin = TryReadBuildOrigin(yara);
        }

        return new YaraEngineInfo
        {
            IsAvailable = true,
            YaraExecutablePath = yara,
            YaracExecutablePath = yarac,
            Version = _cachedVersion,
            BuildOrigin = _cachedBuildOrigin,
            TotalRuleFiles = files.Count,
            ValidRuleFiles = validFiles.Count,
            InvalidRuleFiles = invalidFiles.Count,
            DisabledRuleFiles = disabledFiles.Count,
            ActiveRuleCount = validFiles.Sum(f => f.RuleCount),
            CompiledBundleReady = File.Exists(CompiledBundlePath),
            LastCompiledAt = _lastCompiledAt ?? (File.Exists(CompiledBundlePath) ? new DateTimeOffset(File.GetLastWriteTimeUtc(CompiledBundlePath), TimeSpan.Zero) : null)
        };
    }

    private static string? TryReadBuildOrigin(string yaraPath)
    {
        try
        {
            var metaPath = Path.Combine(Path.GetDirectoryName(yaraPath) ?? string.Empty, "yara-build-info.json");
            if (!File.Exists(metaPath))
                return null;

            using var doc = JsonDocument.Parse(File.ReadAllText(metaPath));
            if (doc.RootElement.TryGetProperty("origin", out var origin) && origin.ValueKind == JsonValueKind.String)
                return origin.GetString();
        }
        catch
        {
            // Optional metadata file
        }
        return null;
    }

    private void EnsureDirectories()
    {
        Directory.CreateDirectory(BundledRulesStoreDir);
        Directory.CreateDirectory(UserRulesStoreDir);
        Directory.CreateDirectory(RepoRulesStoreDir);
        Directory.CreateDirectory(CompiledDir);
    }

    private void SyncBundledRulesUnlocked()
    {
        var sourceDir = FindBundledRulesSourceDirectory();
        if (sourceDir is null)
            return;

        foreach (var srcFile in Directory.EnumerateFiles(sourceDir, "*.*", SearchOption.TopDirectoryOnly)
                     .Where(IsSupportedRuleExtension))
        {
            var destPath = Path.Combine(BundledRulesStoreDir, Path.GetFileName(srcFile));
            if (!File.Exists(destPath) || !string.Equals(ComputeFileSha256(srcFile), ComputeFileSha256(destPath), StringComparison.OrdinalIgnoreCase))
            {
                File.Copy(srcFile, destPath, overwrite: true);
            }
        }
    }

    private List<YaraRuleFileInfo> EnumerateRuleFilesUnlocked()
    {
        var results = new List<YaraRuleFileInfo>();
        AddRuleFilesFromDir(BundledRulesStoreDir, YaraRuleSource.Bundled, "Bundled (BECETTI)", results);
        AddRuleFilesFromDir(UserRulesStoreDir, YaraRuleSource.User, "User Imported", results);
        AddRuleFilesFromDir(RepoRulesStoreDir, YaraRuleSource.Repository, "Trusted Repository", results);
        return results.OrderBy(r => r.Source).ThenBy(r => r.FileName, StringComparer.OrdinalIgnoreCase).ToList();
    }

    private void AddRuleFilesFromDir(string dir, YaraRuleSource source, string sourceName, List<YaraRuleFileInfo> results)
    {
        if (!Directory.Exists(dir))
            return;

        foreach (var path in Directory.EnumerateFiles(dir, "*.*", SearchOption.TopDirectoryOnly)
                     .Where(IsSupportedRuleExtension))
        {
            var fileName = Path.GetFileName(path);
            var id = MakeRuleId(source, fileName);
            var sha = ComputeFileSha256(path);
            var fi = new FileInfo(path);
            var isEnabled = !_storeState.DisabledRuleIds.Contains(id);

            var status = isEnabled ? YaraRuleValidationStatus.Unknown : YaraRuleValidationStatus.Disabled;
            IReadOnlyList<string> ruleNames = Array.Empty<string>();
            string? validationError = null;
            DateTimeOffset? lastValidated = null;

            if (_storeState.ValidationCache.TryGetValue(id, out var cached) &&
                string.Equals(cached.Sha256, sha, StringComparison.OrdinalIgnoreCase))
            {
                ruleNames = cached.RuleNames;
                validationError = cached.ErrorMessage;
                lastValidated = cached.LastValidatedAt;
                if (isEnabled)
                    status = cached.IsValid ? YaraRuleValidationStatus.Valid : YaraRuleValidationStatus.Invalid;
            }
            else
            {
                ruleNames = ExtractRuleNamesFromSource(path);
            }

            results.Add(new YaraRuleFileInfo
            {
                Id = id,
                FileName = fileName,
                FullPath = path,
                Source = source,
                SourceName = sourceName,
                IsEnabled = isEnabled,
                Status = status,
                RuleCount = ruleNames.Count,
                RuleNames = ruleNames,
                ValidationError = validationError,
                LastValidatedAt = lastValidated,
                FileSizeBytes = fi.Length,
                Sha256 = sha
            });
        }
    }

    private void LoadStoreStateUnlocked()
    {
        try
        {
            if (File.Exists(StoreStatePath))
            {
                var loaded = JsonSerializer.Deserialize<YaraRuleStoreState>(File.ReadAllText(StoreStatePath), JsonOptions);
                if (loaded is not null)
                {
                    _storeState = loaded;
                    return;
                }
            }
        }
        catch
        {
            // Recover cleanly from corrupt state cache
        }
        _storeState = new YaraRuleStoreState();
    }

    private void SaveStoreStateUnlocked()
    {
        try
        {
            Directory.CreateDirectory(YaraRootDir);
            File.WriteAllText(StoreStatePath, JsonSerializer.Serialize(_storeState, JsonOptions));
        }
        catch
        {
            // Non-fatal
        }
    }

    private static void EnumerateFilesSafely(
        string rootDir,
        List<string> files,
        List<YaraScanError> errors,
        ref int filesSkipped,
        CancellationToken ct)
    {
        var pendingDirs = new Stack<string>();
        pendingDirs.Push(rootDir);

        while (pendingDirs.Count > 0)
        {
            if (ct.IsCancellationRequested)
                break;

            var dir = pendingDirs.Pop();
            try
            {
                foreach (var file in Directory.EnumerateFiles(dir))
                    files.Add(file);

                foreach (var sub in Directory.EnumerateDirectories(dir))
                {
                    var attr = File.GetAttributes(sub);
                    // Avoid reparse-point / symlink loops
                    if ((attr & FileAttributes.ReparsePoint) != 0)
                        continue;
                    pendingDirs.Push(sub);
                }
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
            {
                filesSkipped++;
                errors.Add(new YaraScanError
                {
                    FilePath = dir,
                    Code = "DIR_ACCESS_ERROR",
                    Message = ex.Message
                });
            }
        }
    }

    // ---------- Pure static parsers (unit-tested) ----------

    /// <summary>
    /// Parses genuine yara64.exe stdout produced with flags <c>-m -s -g</c>.
    /// Header line format:
    /// <c>RuleName [tag1,tag2] [key1="val1",key2=42] C:\path\to\file</c>
    /// Matched string lines:
    /// <c>0x0:$id: matched text</c>
    /// </summary>
    internal static IReadOnlyList<YaraRuleMatch> ParseYaraScanOutput(string stdout, string fallbackFilePath)
    {
        var matches = new List<YaraRuleMatch>();
        if (string.IsNullOrWhiteSpace(stdout))
            return matches;

        YaraRuleMatchBuilder? current = null;
        var lines = stdout.Replace("\r\n", "\n").Split('\n');

        foreach (var rawLine in lines)
        {
            if (string.IsNullOrWhiteSpace(rawLine))
                continue;

            var strMatch = MatchedStringLineRegex.Match(rawLine);
            if (strMatch.Success && current is not null)
            {
                current.MatchedStrings.Add(new YaraMatchedString
                {
                    Offset = strMatch.Groups[1].Value,
                    Identifier = strMatch.Groups[2].Value,
                    Preview = strMatch.Groups[3].Value.Trim()
                });
                continue;
            }

            if (current is not null)
            {
                matches.Add(current.Build());
                current = null;
            }

            var parsedHeader = ParseMatchHeaderLine(rawLine, fallbackFilePath);
            if (parsedHeader is not null)
                current = parsedHeader;
        }

        if (current is not null)
            matches.Add(current.Build());

        return matches;
    }

    private static YaraRuleMatchBuilder? ParseMatchHeaderLine(string line, string fallbackFilePath)
    {
        var pos = 0;
        SkipSpaces(line, ref pos);
        var nameStart = pos;
        while (pos < line.Length && !char.IsWhiteSpace(line[pos]))
            pos++;

        if (pos == nameStart)
            return null;

        var ruleName = line[nameStart..pos];
        var tags = new List<string>();
        var metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        // Parse up to two bracket blocks: [tags] then [metadata] (produced by -g -m)
        var blocks = new List<string>();
        for (var b = 0; b < 2; b++)
        {
            SkipSpaces(line, ref pos);
            if (pos < line.Length && line[pos] == '[')
            {
                var block = ReadBracketBlock(line, ref pos);
                if (block is not null)
                    blocks.Add(block);
            }
            else
            {
                break;
            }
        }

        if (blocks.Count == 2)
        {
            tags.AddRange(ParseTagsBlock(blocks[0]));
            ParseMetadataBlock(blocks[1], metadata);
        }
        else if (blocks.Count == 1)
        {
            if (blocks[0].Contains('='))
                ParseMetadataBlock(blocks[0], metadata);
            else
                tags.AddRange(ParseTagsBlock(blocks[0]));
        }

        SkipSpaces(line, ref pos);
        var filePath = pos < line.Length ? line[pos..].Trim() : fallbackFilePath;
        if (string.IsNullOrWhiteSpace(filePath))
            filePath = fallbackFilePath;

        return new YaraRuleMatchBuilder
        {
            RuleName = ruleName,
            FilePath = filePath,
            Tags = tags,
            Metadata = metadata
        };
    }

    private static string? ReadBracketBlock(string line, ref int pos)
    {
        if (pos >= line.Length || line[pos] != '[')
            return null;

        pos++; // consume '['
        var start = pos;
        var inQuotes = false;
        while (pos < line.Length)
        {
            var c = line[pos];
            if (inQuotes)
            {
                if (c == '\\' && pos + 1 < line.Length)
                {
                    pos += 2;
                    continue;
                }
                if (c == '"')
                    inQuotes = false;
            }
            else
            {
                if (c == '"')
                    inQuotes = true;
                else if (c == ']')
                {
                    var content = line[start..pos];
                    pos++; // consume ']'
                    return content;
                }
            }
            pos++;
        }

        return null;
    }

    private static IEnumerable<string> ParseTagsBlock(string block) =>
        block.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    internal static void ParseMetadataBlock(string block, Dictionary<string, string> target)
    {
        var i = 0;
        while (i < block.Length)
        {
            while (i < block.Length && (block[i] == ',' || char.IsWhiteSpace(block[i])))
                i++;
            if (i >= block.Length)
                break;

            var keyStart = i;
            while (i < block.Length && block[i] != '=' && block[i] != ',')
                i++;
            var key = block[keyStart..i].Trim();
            if (i >= block.Length || block[i] != '=')
                break;

            i++; // consume '='
            string val;
            if (i < block.Length && block[i] == '"')
            {
                i++; // consume opening '"'
                var sb = new StringBuilder();
                while (i < block.Length)
                {
                    var c = block[i];
                    if (c == '\\' && i + 1 < block.Length)
                    {
                        var next = block[i + 1];
                        sb.Append(next switch
                        {
                            'n' => '\n',
                            'r' => '\r',
                            't' => '\t',
                            '"' => '"',
                            '\\' => '\\',
                            _ => next
                        });
                        i += 2;
                        continue;
                    }
                    if (c == '"')
                    {
                        i++; // consume closing '"'
                        break;
                    }
                    sb.Append(c);
                    i++;
                }
                val = sb.ToString();
            }
            else
            {
                var valStart = i;
                while (i < block.Length && block[i] != ',')
                    i++;
                val = block[valStart..i].Trim();
            }

            if (!string.IsNullOrWhiteSpace(key))
                target[key] = val;
        }
    }

    internal static IReadOnlyList<string> ExtractRuleNamesFromSource(string filePath)
    {
        try
        {
            var text = File.ReadAllText(filePath);
            // Strip /* ... */ block comments and // line comments before extracting rule declarations
            var stripped = Regex.Replace(text, @"/\*[\s\S]*?\*/|//[^\r\n]*", string.Empty);
            return RuleDeclarationRegex.Matches(stripped)
                .Select(m => m.Groups[1].Value)
                .Distinct(StringComparer.Ordinal)
                .ToList();
        }
        catch
        {
            return Array.Empty<string>();
        }
    }

    internal static bool IsSupportedRuleExtension(string path)
    {
        var ext = Path.GetExtension(path);
        return string.Equals(ext, ".yar", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(ext, ".yara", StringComparison.OrdinalIgnoreCase);
    }

    private static string SanitizeRuleFileName(string name)
    {
        var invalid = Path.GetInvalidFileNameChars();
        var clean = new string(name.Select(c => invalid.Contains(c) ? '_' : c).ToArray());
        if (!IsSupportedRuleExtension(clean))
            clean += ".yar";
        return clean;
    }

    private static string MakeRuleId(YaraRuleSource source, string fileName) =>
        $"{source.ToString().ToLowerInvariant()}:{fileName.ToLowerInvariant()}";

    private static string ComputeFileSha256(string path)
    {
        using var stream = File.OpenRead(path);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    private static void SkipSpaces(string s, ref int pos)
    {
        while (pos < s.Length && char.IsWhiteSpace(s[pos]))
            pos++;
    }

    private static IEnumerable<string> SplitNonEmptyLines(string text) =>
        string.IsNullOrWhiteSpace(text)
            ? Array.Empty<string>()
            : text.Replace("\r\n", "\n").Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    // ---------- Managed process execution ----------

    private sealed record NativeProcessRun(int ExitCode, string Output, string Error);

    private static async Task<OperationResult<NativeProcessRun>> RunProcessAsync(
        string fileName,
        IReadOnlyList<string> arguments,
        TimeSpan timeout,
        CancellationToken ct)
    {
        Process? process = null;
        try
        {
            var startInfo = new ProcessStartInfo
            {
                FileName = fileName,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8
            };
            foreach (var arg in arguments)
                startInfo.ArgumentList.Add(arg);

            process = new Process { StartInfo = startInfo };
            process.Start();

            using var timeoutCts = new CancellationTokenSource(timeout);
            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct, timeoutCts.Token);

            var outTask = process.StandardOutput.ReadToEndAsync(linkedCts.Token);
            var errTask = process.StandardError.ReadToEndAsync(linkedCts.Token);

            await process.WaitForExitAsync(linkedCts.Token).ConfigureAwait(false);
            var output = await outTask.ConfigureAwait(false);
            var error = await errTask.ConfigureAwait(false);

            return OperationResult<NativeProcessRun>.Ok(new NativeProcessRun(process.ExitCode, output, error));
        }
        catch (OperationCanceledException)
        {
            TryKill(process);
            return OperationResult<NativeProcessRun>.Fail(
                ct.IsCancellationRequested ? "Scan cancelled by user." : $"Native YARA process timed out after {timeout.TotalSeconds:F0}s.",
                ct.IsCancellationRequested ? "CANCELLED" : "TIMEOUT");
        }
        catch (Exception ex)
        {
            TryKill(process);
            return OperationResult<NativeProcessRun>.Fail($"Failed to execute '{Path.GetFileName(fileName)}': {ex.Message}", "PROCESS_FAILED");
        }
        finally
        {
            process?.Dispose();
        }
    }

    private static void TryKill(Process? process)
    {
        try
        {
            if (process is not null && !process.HasExited)
                process.Kill(entireProcessTree: true);
        }
        catch
        {
            // Ignore race on exit
        }
    }

    private sealed class YaraRuleMatchBuilder
    {
        public string RuleName { get; init; } = string.Empty;
        public string FilePath { get; init; } = string.Empty;
        public List<string> Tags { get; init; } = new();
        public Dictionary<string, string> Metadata { get; init; } = new(StringComparer.OrdinalIgnoreCase);
        public List<YaraMatchedString> MatchedStrings { get; init; } = new();

        public YaraRuleMatch Build()
        {
            Metadata.TryGetValue("description", out var desc);
            Metadata.TryGetValue("author", out var author);
            Metadata.TryGetValue("severity", out var severity);
            Metadata.TryGetValue("category", out var category);
            Metadata.TryGetValue("reference", out var reference);

            return new YaraRuleMatch
            {
                RuleName = RuleName,
                FilePath = FilePath,
                Description = desc ?? string.Empty,
                Author = author ?? string.Empty,
                Severity = string.IsNullOrWhiteSpace(severity) ? "Medium" : severity,
                Category = string.IsNullOrWhiteSpace(category) ? "Suspicious" : category,
                Reference = reference ?? string.Empty,
                Tags = Tags,
                Metadata = Metadata,
                MatchedStrings = MatchedStrings
            };
        }
    }

    private sealed class YaraRuleStoreState
    {
        public HashSet<string> DisabledRuleIds { get; set; } = new(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, CachedRuleValidation> ValidationCache { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    }

    private sealed class CachedRuleValidation
    {
        public string Sha256 { get; set; } = string.Empty;
        public bool IsValid { get; set; }
        public List<string> RuleNames { get; set; } = new();
        public string? ErrorMessage { get; set; }
        public DateTimeOffset LastValidatedAt { get; set; }
    }
}
