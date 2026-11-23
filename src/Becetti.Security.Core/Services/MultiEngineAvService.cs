using System.Diagnostics;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

public interface IMultiEngineAvService
{
    Task<OperationResult<IReadOnlyList<AvEngineInfo>>> GetEnginesStatusAsync(CancellationToken ct = default);
    Task<OperationResult<AvEngineInfo>> InstallOrUpdateOpenSourceEngineAsync(string engineId, IProgress<string>? progress = null, CancellationToken ct = default);
    Task<OperationResult<string>> UpdateClamAvSignaturesAsync(CancellationToken ct = default);
    Task<OperationResult<MultiEngineScanReport>> ScanTargetWithAllEnginesAsync(string targetPath, CancellationToken ct = default);
}

/// <summary>
/// 5-Engine Open-Source &amp; Local Multi-AV Consensus Orchestrator (ZERO API keys, ZERO cloud uploads).
/// Unifies:
///   1. Microsoft Defender (MpCmdRun.exe — built-in Windows)
///   2. Native YARA v4.6.0 (yara64.exe — VirusTotal BSD-3-Clause, 43 built-in rules)
///   3. ClamAV (clamscan.exe + freshclam.exe — Cisco Talos GPLv2 official Windows x64 zip)
///   4. YARA-X (yr.exe — VirusTotal BSD-3-Clause Rust next-gen engine)
///   5. Mandiant CAPA (capa.exe — Google Cloud / Mandiant Apache-2.0 malware capability detector)
/// </summary>
public sealed class MultiEngineAvService : IMultiEngineAvService
{
    private readonly HttpClient _http;
    private readonly ISettingsService _settings;
    private readonly IDefenderService _defender;
    private readonly IYaraEngineService _yara;
    private readonly string _enginesRoot;

    public MultiEngineAvService(
        HttpClient http,
        ISettingsService settings,
        IDefenderService defender,
        IYaraEngineService yara)
    {
        _http = http;
        _settings = settings;
        _defender = defender;
        _yara = yara;
        _enginesRoot = Path.Combine(settings.DataDirectory, "engines");
        Directory.CreateDirectory(_enginesRoot);
    }

    public async Task<OperationResult<IReadOnlyList<AvEngineInfo>>> GetEnginesStatusAsync(CancellationToken ct = default)
    {
        var list = new List<AvEngineInfo>();

        // 1. Microsoft Defender
        var mpCmd = _defender.FindMpCmdRun();
        list.Add(new AvEngineInfo
        {
            EngineId = "defender",
            Name = "Microsoft Defender",
            VendorAndLicense = "Microsoft · Windows Native",
            Description = "Real-time OS signature & heuristic antivirus scanner via MpCmdRun.exe.",
            IsInstalled = !string.IsNullOrWhiteSpace(mpCmd) && File.Exists(mpCmd),
            CanAutoInstall = false,
            SupportsSignatureUpdate = false,
            Version = !string.IsNullOrWhiteSpace(mpCmd) ? "System Native" : "Unavailable",
            ExecutablePath = mpCmd ?? string.Empty,
            StatusNote = !string.IsNullOrWhiteSpace(mpCmd) ? "Ready for multi-engine consensus scanning." : "MpCmdRun.exe not detected."
        });

        // 2. Bundled Native YARA v4.6.0
        var yaraInfoRes = await _yara.GetEngineInfoAsync(ct).ConfigureAwait(false);
        var yaraInfo = yaraInfoRes.Value;
        bool yaraOk = yaraInfo?.IsAvailable == true;
        list.Add(new AvEngineInfo
        {
            EngineId = "yara",
            Name = "Native YARA Engine",
            VendorAndLicense = "VirusTotal · BSD-3-Clause (Open Source)",
            Description = "Official VirusTotal x64 pattern-matching scanner with 43 built-in MITRE ATT&CK rules.",
            IsInstalled = yaraOk,
            CanAutoInstall = false,
            SupportsSignatureUpdate = false,
            Version = yaraOk ? (yaraInfo?.Version ?? "4.6.0") : "Unavailable",
            ExecutablePath = yaraInfo?.YaraExecutablePath ?? string.Empty,
            StatusNote = yaraOk
                ? $"Bundled · {yaraInfo?.ActiveRuleCount ?? 0} active compiled rules ready."
                : "Bundled yara64.exe not found."
        });

        // 3. Cisco Talos ClamAV (GPLv2)
        var clamExe = FindClamScanExecutable();
        bool clamInstalled = !string.IsNullOrWhiteSpace(clamExe);
        var clamDbDir = GetClamDbDirectory();
        bool hasCvd = Directory.Exists(clamDbDir) &&
                      Directory.EnumerateFiles(clamDbDir, "*.c*d").Any();
        string clamVer = clamInstalled ? await ReadToolVersionAsync(clamExe!, "--version", ct).ConfigureAwait(false) : "Not installed";
        list.Add(new AvEngineInfo
        {
            EngineId = "clamav",
            Name = "ClamAV Antivirus Engine",
            VendorAndLicense = "Cisco Talos · GPLv2 (Open Source, 0 API Keys)",
            Description = "World's #1 open-source signature antivirus engine with millions of virus, trojan, and document malware signatures.",
            IsInstalled = clamInstalled,
            CanAutoInstall = true,
            SupportsSignatureUpdate = true,
            Version = string.IsNullOrWhiteSpace(clamVer) ? "Installed" : clamVer,
            ExecutablePath = clamExe ?? string.Empty,
            StatusNote = !clamInstalled
                ? "Click 'Install ClamAV' to download official Cisco Talos Windows x64 binaries from GitHub."
                : (hasCvd ? "Engine + CVD virus signature databases ready." : "Engine installed — click 'Update ClamAV DB' to download virus definitions via freshclam.")
        });

        // 4. VirusTotal YARA-X (Rust Next-Gen)
        var yrExe = FindYaraXExecutable();
        bool yrInstalled = !string.IsNullOrWhiteSpace(yrExe);
        string yrVer = yrInstalled ? await ReadToolVersionAsync(yrExe!, "--version", ct).ConfigureAwait(false) : "Not installed";
        list.Add(new AvEngineInfo
        {
            EngineId = "yarax",
            Name = "VirusTotal YARA-X (Rust)",
            VendorAndLicense = "VirusTotal · BSD-3-Clause (Open Source, 0 API Keys)",
            Description = "Next-generation pure-Rust rewrite of YARA — faster, memory-safe, production engine running at VirusTotal.",
            IsInstalled = yrInstalled,
            CanAutoInstall = true,
            SupportsSignatureUpdate = false,
            Version = string.IsNullOrWhiteSpace(yrVer) ? "Installed" : yrVer,
            ExecutablePath = yrExe ?? string.Empty,
            StatusNote = yrInstalled
                ? "Ready — executes managed YARA rules via Rust yr.exe."
                : "Click 'Install YARA-X' to download official VirusTotal Windows x64 binary (~9 MB)."
        });

        // 5. Mandiant CAPA (Apache-2.0)
        var capaExe = FindCapaExecutable();
        bool capaInstalled = !string.IsNullOrWhiteSpace(capaExe);
        string capaVer = capaInstalled ? await ReadToolVersionAsync(capaExe!, "--version", ct).ConfigureAwait(false) : "Not installed";
        list.Add(new AvEngineInfo
        {
            EngineId = "capa",
            Name = "Mandiant CAPA Analyzer",
            VendorAndLicense = "Mandiant / Google Cloud · Apache-2.0 (Open Source)",
            Description = "Automatically identifies malware capabilities (ransomware, C2, keylogger, anti-VM, injection) mapped to MITRE ATT&CK.",
            IsInstalled = capaInstalled,
            CanAutoInstall = true,
            SupportsSignatureUpdate = false,
            Version = string.IsNullOrWhiteSpace(capaVer) ? "Installed" : capaVer,
            ExecutablePath = capaExe ?? string.Empty,
            StatusNote = capaInstalled
                ? "Ready — analyzes PE/DLL binaries for ATT&CK malware behaviors."
                : "Click 'Install CAPA' to download official Mandiant Windows x64 binary (~36 MB)."
        });

        int ready = list.Count(e => e.IsInstalled);
        return OperationResult<IReadOnlyList<AvEngineInfo>>.Ok(list, $"{ready}/{list.Count} local open-source antivirus engines ready.");
    }

    public async Task<OperationResult<AvEngineInfo>> InstallOrUpdateOpenSourceEngineAsync(
        string engineId,
        IProgress<string>? progress = null,
        CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
            return OperationResult<AvEngineInfo>.Fail("Open-source engine binary installer requires Windows x64.", "UNSUPPORTED_OS");

        var (repo, pattern, targetSubDir) = engineId.ToLowerInvariant() switch
        {
            "clamav" => ("Cisco-Talos/clamav", @"clamav-.*win\.x64\.zip$", "clamav"),
            "yarax" => ("VirusTotal/yara-x", @"^yara-x-v.*-x86_64-pc-windows-msvc\.zip$", "yarax"),
            "capa" => ("mandiant/capa", @"^capa-v.*-windows\.zip$", "capa"),
            _ => (string.Empty, string.Empty, string.Empty)
        };

        if (string.IsNullOrEmpty(repo))
            return OperationResult<AvEngineInfo>.Fail($"Engine '{engineId}' is built-in or unsupported for auto-install.");

        try
        {
            progress?.Report($"Querying official GitHub Releases for {repo}…");
            using var req = new HttpRequestMessage(HttpMethod.Get, $"https://api.github.com/repos/{repo}/releases/latest");
            req.Headers.UserAgent.ParseAdd("BECETTI-SECURITY/1.0");
            req.Headers.Accept.ParseAdd("application/vnd.github+json");

            using var resp = await _http.SendAsync(req, ct).ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode)
                return OperationResult<AvEngineInfo>.Fail($"GitHub Releases API returned HTTP {(int)resp.StatusCode} for {repo}.");

            var releaseJson = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            var (tag, assetName, downloadUrl) = SelectOfficialReleaseAssetUrl(releaseJson, pattern);
            if (string.IsNullOrWhiteSpace(downloadUrl))
                return OperationResult<AvEngineInfo>.Fail($"Could not locate official Windows x64 ZIP asset in {repo} release '{tag}'.");

            progress?.Report($"Downloading official {assetName} ({tag}) from GitHub…");
            var tempZip = Path.Combine(Path.GetTempPath(), $"becetti-{engineId}-{Guid.NewGuid():N}.zip");
            try
            {
                using var dlReq = new HttpRequestMessage(HttpMethod.Get, downloadUrl);
                dlReq.Headers.UserAgent.ParseAdd("BECETTI-SECURITY/1.0");
                using var dlResp = await _http.SendAsync(dlReq, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
                dlResp.EnsureSuccessStatusCode();

                await using (var src = await dlResp.Content.ReadAsStreamAsync(ct).ConfigureAwait(false))
                await using (var dst = File.Create(tempZip))
                {
                    await src.CopyToAsync(dst, ct).ConfigureAwait(false);
                }

                progress?.Report($"Extracting {assetName} into local engines directory…");
                var installDir = Path.Combine(_enginesRoot, targetSubDir);
                if (Directory.Exists(installDir))
                {
                    try { Directory.Delete(installDir, recursive: true); } catch { }
                }
                Directory.CreateDirectory(installDir);
                ZipFile.ExtractToDirectory(tempZip, installDir, overwriteFiles: true);

                if (engineId.Equals("clamav", StringComparison.OrdinalIgnoreCase))
                    EnsureFreshClamConfig();
            }
            finally
            {
                try { if (File.Exists(tempZip)) File.Delete(tempZip); } catch { }
            }

            var statusRes = await GetEnginesStatusAsync(ct).ConfigureAwait(false);
            var updated = statusRes.Value?.FirstOrDefault(e => e.EngineId.Equals(engineId, StringComparison.OrdinalIgnoreCase));
            if (updated is null || !updated.IsInstalled)
                return OperationResult<AvEngineInfo>.Fail($"Extracted {assetName}, but expected executable was not located.");

            return OperationResult<AvEngineInfo>.Ok(updated, $"Installed official {updated.Name} ({tag}) from github.com/{repo}!");
        }
        catch (Exception ex)
        {
            return OperationResult<AvEngineInfo>.Fail($"Failed to install {engineId}: {ex.Message}");
        }
    }

    public async Task<OperationResult<string>> UpdateClamAvSignaturesAsync(CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
            return OperationResult<string>.Fail("ClamAV freshclam requires Windows.", "UNSUPPORTED_OS");

        var freshclam = FindClamBinary("freshclam.exe");
        if (string.IsNullOrWhiteSpace(freshclam))
            return OperationResult<string>.Fail("ClamAV is not installed yet. Click 'Install ClamAV' first.");

        var confPath = EnsureFreshClamConfig();
        var (exit, stdout, stderr) = await RunProcessAsync(freshclam, $"--config-file=\"{confPath}\"", TimeSpan.FromMinutes(4), ct).ConfigureAwait(false);
        var combined = $"{stdout}\n{stderr}".Trim();

        if (exit == 0)
            return OperationResult<string>.Ok(combined, "ClamAV virus signature databases (main.cvd / daily.cvd / bytecode.cvd) updated successfully!");

        return OperationResult<string>.Fail($"freshclam exited with code {exit}: {TrimOutput(combined, 400)}");
    }

    public async Task<OperationResult<MultiEngineScanReport>> ScanTargetWithAllEnginesAsync(string targetPath, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(targetPath) || (!File.Exists(targetPath) && !Directory.Exists(targetPath)))
            return OperationResult<MultiEngineScanReport>.Fail("Select a valid existing file or folder to scan.");

        bool isFile = File.Exists(targetPath);
        string sha256 = isFile ? await ComputeFileSha256Async(targetPath, ct).ConfigureAwait(false) : "(Directory)";

        var tasks = new List<Task<SingleEngineVerdict>>
        {
            ScanWithDefenderAsync(targetPath, ct),
            ScanWithYaraAsync(targetPath, ct),
            ScanWithClamAvAsync(targetPath, ct),
            ScanWithYaraXAsync(targetPath, ct)
        };

        var capaCapabilities = new List<string>();
        Task<(SingleEngineVerdict Verdict, List<string> Caps)>? capaTask = isFile
            ? ScanWithCapaAsync(targetPath, ct)
            : null;

        var results = (await Task.WhenAll(tasks).ConfigureAwait(false)).ToList();
        if (capaTask is not null)
        {
            var (capaVerdict, caps) = await capaTask.ConfigureAwait(false);
            results.Add(capaVerdict);
            capaCapabilities.AddRange(caps);
        }

        int executed = results.Count(r => r.Verdict is not "Skipped");
        int flagged = results.Count(r => r.ThreatDetected);
        bool anySuspicious = results.Any(r => r.Verdict == "Suspicious");

        string overall = flagged >= 2 ? "MALICIOUS (Multi-Engine Consensus)"
            : flagged == 1 ? "MALICIOUS / DETECTED (1 Engine)"
            : anySuspicious ? "SUSPICIOUS (Behavioral Capabilities)"
            : "CLEAN (All Engines)";

        var summary = $"Consensus: {flagged}/{executed} engine(s) flagged threat · Verdict: {overall}";

        return OperationResult<MultiEngineScanReport>.Ok(new MultiEngineScanReport
        {
            TargetPath = targetPath,
            TargetSha256 = sha256,
            ScannedAt = DateTimeOffset.UtcNow,
            EnginesExecuted = executed,
            EnginesFlagged = flagged,
            OverallVerdict = overall,
            EngineResults = results,
            CapaCapabilities = capaCapabilities,
            Summary = summary
        }, summary);
    }

    private async Task<SingleEngineVerdict> ScanWithDefenderAsync(string targetPath, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        if (!OperatingSystem.IsWindows() || string.IsNullOrWhiteSpace(_defender.FindMpCmdRun()))
            return new SingleEngineVerdict { EngineId = "defender", EngineName = "Microsoft Defender", Verdict = "Skipped", DetectionSummary = "MpCmdRun.exe unavailable on this host." };

        var res = await _defender.RunScanAsync(DefenderScanType.Custom, targetPath, ct).ConfigureAwait(false);
        sw.Stop();

        if (!res.Success || res.Value is null)
            return new SingleEngineVerdict { EngineId = "defender", EngineName = "Microsoft Defender", Verdict = "Error", DetectionSummary = res.Message, DurationMs = sw.ElapsedMilliseconds };

        if (res.Value.ThreatFound)
            return new SingleEngineVerdict { EngineId = "defender", EngineName = "Microsoft Defender", Verdict = "Malicious", ThreatDetected = true, DetectionSummary = "Threat detected by Microsoft Defender MpCmdRun!", DurationMs = sw.ElapsedMilliseconds };

        return new SingleEngineVerdict { EngineId = "defender", EngineName = "Microsoft Defender", Verdict = "Clean", ThreatDetected = false, DetectionSummary = "No threats detected.", DurationMs = sw.ElapsedMilliseconds };
    }

    private async Task<SingleEngineVerdict> ScanWithYaraAsync(string targetPath, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        var info = await _yara.GetEngineInfoAsync(ct).ConfigureAwait(false);
        if (!info.Success || info.Value?.IsAvailable != true)
            return new SingleEngineVerdict { EngineId = "yara", EngineName = "Native YARA v4.6.0", Verdict = "Skipped", DetectionSummary = "Native YARA binary unavailable." };

        var scan = await _yara.ScanAsync(targetPath, null, ct).ConfigureAwait(false);
        sw.Stop();
        if (!scan.Success || scan.Value is null)
            return new SingleEngineVerdict { EngineId = "yara", EngineName = "Native YARA v4.6.0", Verdict = "Error", DetectionSummary = scan.Message, DurationMs = sw.ElapsedMilliseconds };

        var matches = scan.Value.Matches;
        if (matches.Count > 0)
        {
            var ruleNames = matches.Select(m => m.RuleName).Distinct().Take(8).ToList();
            return new SingleEngineVerdict
            {
                EngineId = "yara",
                EngineName = "Native YARA v4.6.0",
                Verdict = "Malicious",
                ThreatDetected = true,
                DetectionSummary = $"{matches.Count} rule match(es): {string.Join(", ", ruleNames)}",
                Indicators = ruleNames,
                DurationMs = sw.ElapsedMilliseconds
            };
        }

        return new SingleEngineVerdict
        {
            EngineId = "yara",
            EngineName = "Native YARA v4.6.0",
            Verdict = "Clean",
            ThreatDetected = false,
            DetectionSummary = $"Clean across {scan.Value.TotalRulesLoaded} compiled built-in & custom rules.",
            DurationMs = sw.ElapsedMilliseconds
        };
    }

    private async Task<SingleEngineVerdict> ScanWithClamAvAsync(string targetPath, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        var clamExe = FindClamScanExecutable();
        if (string.IsNullOrWhiteSpace(clamExe))
            return new SingleEngineVerdict { EngineId = "clamav", EngineName = "ClamAV (Cisco Talos)", Verdict = "Skipped", DetectionSummary = "Not installed (click 'Install ClamAV' above)." };

        var dbDir = GetClamDbDirectory();
        if (!Directory.Exists(dbDir) || !Directory.EnumerateFiles(dbDir, "*.c*d").Any())
            return new SingleEngineVerdict { EngineId = "clamav", EngineName = "ClamAV (Cisco Talos)", Verdict = "Skipped", DetectionSummary = "ClamAV installed — run 'Update ClamAV DB' to fetch virus definitions first." };

        var args = $"--database=\"{dbDir}\" --no-summary --infected --recursive \"{targetPath}\"";
        var (exit, stdout, stderr) = await RunProcessAsync(clamExe, args, TimeSpan.FromMinutes(3), ct).ConfigureAwait(false);
        sw.Stop();

        return ParseClamScanOutput(exit, stdout, stderr, sw.ElapsedMilliseconds);
    }

    private async Task<SingleEngineVerdict> ScanWithYaraXAsync(string targetPath, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        var yrExe = FindYaraXExecutable();
        if (string.IsNullOrWhiteSpace(yrExe))
            return new SingleEngineVerdict { EngineId = "yarax", EngineName = "VirusTotal YARA-X (Rust)", Verdict = "Skipped", DetectionSummary = "Not installed (click 'Install YARA-X' above)." };

        var rulesRes = await _yara.GetRuleFilesAsync(ct).ConfigureAwait(false);
        var validFiles = rulesRes.Value?
            .Where(r => r.IsEnabled && r.Status == YaraRuleValidationStatus.Valid && File.Exists(r.FullPath))
            .Select(r => $"\"{r.FullPath}\"")
            .ToList() ?? new List<string>();

        if (validFiles.Count == 0)
            return new SingleEngineVerdict { EngineId = "yarax", EngineName = "VirusTotal YARA-X (Rust)", Verdict = "Skipped", DetectionSummary = "No validated YARA rule files available." };

        var args = $"scan --recursive {string.Join(" ", validFiles)} \"{targetPath}\"";
        var (exit, stdout, stderr) = await RunProcessAsync(yrExe, args, TimeSpan.FromMinutes(2), ct).ConfigureAwait(false);
        sw.Stop();

        return ParseYaraXOutput(exit, stdout, stderr, sw.ElapsedMilliseconds);
    }

    private async Task<(SingleEngineVerdict Verdict, List<string> Caps)> ScanWithCapaAsync(string filePath, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        var capaExe = FindCapaExecutable();
        if (string.IsNullOrWhiteSpace(capaExe))
            return (new SingleEngineVerdict { EngineId = "capa", EngineName = "Mandiant CAPA", Verdict = "Skipped", DetectionSummary = "Not installed (click 'Install CAPA' above)." }, new List<string>());

        var ext = Path.GetExtension(filePath).ToLowerInvariant();
        if (ext is not (".exe" or ".dll" or ".sys" or ".scr" or ".ocx" or ".elf" or ".bin"))
            return (new SingleEngineVerdict { EngineId = "capa", EngineName = "Mandiant CAPA", Verdict = "Skipped", DetectionSummary = "CAPA analyzes executable binaries (PE/DLL/ELF)." }, new List<string>());

        var (exit, stdout, stderr) = await RunProcessAsync(capaExe, $"-j \"{filePath}\"", TimeSpan.FromMinutes(2), ct).ConfigureAwait(false);
        sw.Stop();

        return ParseCapaJsonOutput(exit, stdout, stderr, sw.ElapsedMilliseconds);
    }

    // -------------------------------------------------------------------------
    //  Deterministic Parsers (directly unit-tested)
    // -------------------------------------------------------------------------

    internal static (string Tag, string AssetName, string DownloadUrl) SelectOfficialReleaseAssetUrl(string releaseJson, string assetRegex)
    {
        try
        {
            using var doc = JsonDocument.Parse(releaseJson);
            var root = doc.RootElement;
            string tag = root.TryGetProperty("tag_name", out var t) ? t.GetString() ?? "" : "";
            if (root.TryGetProperty("assets", out var assets) && assets.ValueKind == JsonValueKind.Array)
            {
                var rx = new Regex(assetRegex, RegexOptions.IgnoreCase);
                foreach (var a in assets.EnumerateArray())
                {
                    var name = a.TryGetProperty("name", out var n) ? n.GetString() ?? "" : "";
                    var url = a.TryGetProperty("browser_download_url", out var u) ? u.GetString() ?? "" : "";
                    if (rx.IsMatch(name) && !string.IsNullOrWhiteSpace(url))
                        return (tag, name, url);
                }
            }
            return (tag, string.Empty, string.Empty);
        }
        catch { return (string.Empty, string.Empty, string.Empty); }
    }

    internal static SingleEngineVerdict ParseClamScanOutput(int exitCode, string stdout, string stderr, long durationMs)
    {
        var hits = (stdout ?? string.Empty)
            .Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
            .Where(l => l.TrimEnd().EndsWith("FOUND", StringComparison.OrdinalIgnoreCase))
            .Select(l => l.Trim())
            .ToList();

        if (exitCode == 1 || hits.Count > 0)
        {
            return new SingleEngineVerdict
            {
                EngineId = "clamav",
                EngineName = "ClamAV (Cisco Talos)",
                Verdict = "Malicious",
                ThreatDetected = true,
                DetectionSummary = hits.Count > 0 ? string.Join(" | ", hits.Take(5)) : "Malware signature detected (exit 1).",
                Indicators = hits,
                DurationMs = durationMs
            };
        }

        if (exitCode == 0)
        {
            return new SingleEngineVerdict
            {
                EngineId = "clamav",
                EngineName = "ClamAV (Cisco Talos)",
                Verdict = "Clean",
                ThreatDetected = false,
                DetectionSummary = "Clean against ClamAV official CVD virus definitions.",
                DurationMs = durationMs
            };
        }

        return new SingleEngineVerdict
        {
            EngineId = "clamav",
            EngineName = "ClamAV (Cisco Talos)",
            Verdict = "Error",
            DetectionSummary = $"clamscan exited {exitCode}: {TrimOutput(stderr, 220)}",
            DurationMs = durationMs
        };
    }

    internal static SingleEngineVerdict ParseYaraXOutput(int exitCode, string stdout, string stderr, long durationMs)
    {
        var matches = (stdout ?? string.Empty)
            .Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
            .Select(l => l.Trim())
            .Where(l => !string.IsNullOrWhiteSpace(l) && !l.StartsWith("warning:", StringComparison.OrdinalIgnoreCase))
            .ToList();

        if (matches.Count > 0)
        {
            return new SingleEngineVerdict
            {
                EngineId = "yarax",
                EngineName = "VirusTotal YARA-X (Rust)",
                Verdict = "Malicious",
                ThreatDetected = true,
                DetectionSummary = $"{matches.Count} YARA-X match(es): {string.Join(", ", matches.Take(5))}",
                Indicators = matches,
                DurationMs = durationMs
            };
        }

        if (exitCode == 0)
        {
            return new SingleEngineVerdict
            {
                EngineId = "yarax",
                EngineName = "VirusTotal YARA-X (Rust)",
                Verdict = "Clean",
                ThreatDetected = false,
                DetectionSummary = "Clean across Rust YARA-X rule scan.",
                DurationMs = durationMs
            };
        }

        return new SingleEngineVerdict
        {
            EngineId = "yarax",
            EngineName = "VirusTotal YARA-X (Rust)",
            Verdict = "Error",
            DetectionSummary = $"yr.exe exited {exitCode}: {TrimOutput(stderr, 220)}",
            DurationMs = durationMs
        };
    }

    internal static (SingleEngineVerdict Verdict, List<string> Caps) ParseCapaJsonOutput(int exitCode, string stdout, string stderr, long durationMs)
    {
        var caps = new List<string>();
        if (exitCode != 0 || string.IsNullOrWhiteSpace(stdout))
        {
            return (new SingleEngineVerdict
            {
                EngineId = "capa",
                EngineName = "Mandiant CAPA",
                Verdict = "Error",
                DetectionSummary = $"capa.exe exited {exitCode}: {TrimOutput(stderr, 200)}",
                DurationMs = durationMs
            }, caps);
        }

        int highRiskCount = 0;
        try
        {
            using var doc = JsonDocument.Parse(stdout);
            if (doc.RootElement.TryGetProperty("rules", out var rules) && rules.ValueKind == JsonValueKind.Object)
            {
                foreach (var prop in rules.EnumerateObject())
                {
                    var name = prop.Name;
                    string ns = string.Empty;
                    string attack = string.Empty;
                    if (prop.Value.TryGetProperty("meta", out var meta))
                    {
                        if (meta.TryGetProperty("namespace", out var nsEl))
                            ns = nsEl.GetString() ?? string.Empty;
                        if (meta.TryGetProperty("attack", out var attEl) && attEl.ValueKind == JsonValueKind.Array)
                        {
                            var ids = new List<string>();
                            foreach (var a in attEl.EnumerateArray())
                            {
                                if (a.TryGetProperty("id", out var idEl) && !string.IsNullOrWhiteSpace(idEl.GetString()))
                                    ids.Add(idEl.GetString()!);
                            }
                            if (ids.Count > 0) attack = $" [{string.Join(",", ids)}]";
                        }
                    }

                    if (ns.Contains("anti-analysis", StringComparison.OrdinalIgnoreCase) ||
                        ns.Contains("collection", StringComparison.OrdinalIgnoreCase) ||
                        ns.Contains("impact", StringComparison.OrdinalIgnoreCase) ||
                        ns.Contains("persistence", StringComparison.OrdinalIgnoreCase) ||
                        ns.Contains("defense-evasion", StringComparison.OrdinalIgnoreCase) ||
                        ns.Contains("c2", StringComparison.OrdinalIgnoreCase))
                    {
                        highRiskCount++;
                    }

                    caps.Add($"{(string.IsNullOrWhiteSpace(ns) ? "capability" : ns)}: {name}{attack}");
                }
            }
        }
        catch { }

        string verdict = highRiskCount >= 3 ? "Suspicious" : "Clean";
        return (new SingleEngineVerdict
        {
            EngineId = "capa",
            EngineName = "Mandiant CAPA",
            Verdict = verdict,
            ThreatDetected = false,
            DetectionSummary = $"{caps.Count} capability(s) identified ({highRiskCount} high-risk ATT&CK/evasion behaviors).",
            Indicators = caps.Take(10).ToList(),
            DurationMs = durationMs
        }, caps);
    }

    // -------------------------------------------------------------------------
    //  Binary Discovery & Helpers
    // -------------------------------------------------------------------------

    private string? FindClamScanExecutable() => FindClamBinary("clamscan.exe");

    private string? FindClamBinary(string exeName)
    {
        var local = SearchDirectoryForFile(Path.Combine(_enginesRoot, "clamav"), exeName);
        if (local is not null) return local;

        var programFiles = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "ClamAV", exeName);
        if (File.Exists(programFiles)) return programFiles;

        return FindOnPath(exeName);
    }

    private string? FindYaraXExecutable() =>
        SearchDirectoryForFile(Path.Combine(_enginesRoot, "yarax"), "yr.exe") ?? FindOnPath("yr.exe");

    private string? FindCapaExecutable() =>
        SearchDirectoryForFile(Path.Combine(_enginesRoot, "capa"), "capa.exe") ?? FindOnPath("capa.exe");

    private string GetClamDbDirectory()
    {
        var dir = Path.Combine(_enginesRoot, "clamav-db");
        Directory.CreateDirectory(dir);
        return dir;
    }

    private string EnsureFreshClamConfig()
    {
        var dbDir = GetClamDbDirectory();
        var confPath = Path.Combine(_enginesRoot, "freshclam.conf");
        var content =
            $"DatabaseDirectory \"{dbDir}\"\n" +
            "DatabaseMirror database.clamav.net\n" +
            "Checks 12\n" +
            "ConnectTimeout 30\n" +
            "ReceiveTimeout 60\n";
        File.WriteAllText(confPath, content, Encoding.ASCII);
        return confPath;
    }

    private static string? SearchDirectoryForFile(string rootDir, string fileName)
    {
        if (!Directory.Exists(rootDir)) return null;
        try
        {
            return Directory.EnumerateFiles(rootDir, fileName, SearchOption.AllDirectories).FirstOrDefault();
        }
        catch { return null; }
    }

    private static string? FindOnPath(string exeName)
    {
        var pathEnv = Environment.GetEnvironmentVariable("PATH") ?? string.Empty;
        foreach (var dir in pathEnv.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
        {
            try
            {
                var full = Path.Combine(dir.Trim(), exeName);
                if (File.Exists(full)) return full;
            }
            catch { }
        }
        return null;
    }

    private static async Task<string> ReadToolVersionAsync(string exePath, string arg, CancellationToken ct)
    {
        var (exit, stdout, stderr) = await RunProcessAsync(exePath, arg, TimeSpan.FromSeconds(10), ct).ConfigureAwait(false);
        var line = (string.IsNullOrWhiteSpace(stdout) ? stderr : stdout)
            .Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
            .FirstOrDefault()?.Trim() ?? string.Empty;
        return exit == 0 && !string.IsNullOrWhiteSpace(line) ? TrimOutput(line, 48) : "Installed";
    }

    private static async Task<(int ExitCode, string StdOut, string StdErr)> RunProcessAsync(
        string fileName, string args, TimeSpan timeout, CancellationToken ct)
    {
        try
        {
            using var p = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = fileName,
                    Arguments = args,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                }
            };
            p.Start();
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(timeout);
            var outTask = p.StandardOutput.ReadToEndAsync(cts.Token);
            var errTask = p.StandardError.ReadToEndAsync(cts.Token);
            await p.WaitForExitAsync(cts.Token).ConfigureAwait(false);
            return (p.ExitCode, await outTask.ConfigureAwait(false), await errTask.ConfigureAwait(false));
        }
        catch (Exception ex)
        {
            return (-1, string.Empty, ex.Message);
        }
    }

    private static async Task<string> ComputeFileSha256Async(string filePath, CancellationToken ct)
    {
        try
        {
            await using var fs = File.OpenRead(filePath);
            var hash = await SHA256.HashDataAsync(fs, ct).ConfigureAwait(false);
            return Convert.ToHexString(hash).ToLowerInvariant();
        }
        catch { return string.Empty; }
    }

    private static string TrimOutput(string s, int maxLen) =>
        string.IsNullOrWhiteSpace(s) ? string.Empty : (s.Length > maxLen ? s[..maxLen] + "…" : s);
}
