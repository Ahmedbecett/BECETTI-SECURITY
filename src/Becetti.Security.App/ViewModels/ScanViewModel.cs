using Becetti.Security.App.Services;
using Becetti.Security.Core.Models;
using Becetti.Security.Core.Services;

namespace Becetti.Security.App.ViewModels;

/// <summary>
/// Visual state of the robot mascot on the Scan page. Every value here is
/// driven directly by a real scan state (IsScanning / real Defender or native YARA
/// verdict) — never decorative or guessed.
/// </summary>
public enum ScanMascotMood
{
    /// <summary>No scan is running and the last one (if any) is not being shown.</summary>
    Idle,
    /// <summary>A real Defender or native YARA scan is currently in progress.</summary>
    Scanning,
    /// <summary>The last real scan completed with no threat found.</summary>
    Clean,
    /// <summary>The last real scan found a real threat or YARA rule match.</summary>
    Alert
}

/// <summary>
/// Smart Scan page: combines the local native YARA malware-detection engine
/// (VirusTotal/yara x64) with Microsoft Defender (MpCmdRun.exe). Every result
/// is real and verified locally — BECETTI SECURITY never simulates detections.
/// </summary>
public sealed class ScanViewModel : ViewModelBase
{
    private readonly IDefenderService _defender;
    private readonly IYaraEngineService _yara;
    private readonly IEventLogService _events;
    private readonly ISettingsService _settings;
    private readonly SoundService _sound;
    private readonly NotificationService _notifications;

    private string _targetPath = string.Empty;
    private string _scanOutput = string.Empty;
    private string _scanResultText = "No scan started yet.";
    private bool _isScanning;
    private ScanMascotMood _mascotMood = ScanMascotMood.Idle;
    private string _mascotStatusText = "Resting — no scan running right now.";
    private string _elapsedText = string.Empty;
    private ScanOutcome? _lastOutcome;
    private YaraScanReport? _lastYaraReport;
    private DefenderScanType _lastScanType;

    public ScanViewModel(
        IDefenderService defender,
        IYaraEngineService yara,
        IEventLogService events,
        ISettingsService settings,
        SoundService sound,
        NotificationService notifications)
    {
        _defender = defender;
        _yara = yara;
        _events = events;
        _settings = settings;
        _sound = sound;
        _notifications = notifications;

        QuickScanCommand = new RelayCommand(() => RunScanAsync(DefenderScanType.Quick));
        FullScanCommand = new RelayCommand(() => RunScanAsync(DefenderScanType.Full));
        CustomScanCommand = new RelayCommand(() => RunScanAsync(DefenderScanType.Custom, TargetPath));
        YaraCustomScanCommand = new RelayCommand(() => RunYaraScanAsync(TargetPath));
        YaraQuickScanCommand = new RelayCommand(RunYaraQuickScanAsync);
    }

    public RelayCommand QuickScanCommand { get; }
    public RelayCommand FullScanCommand { get; }
    public RelayCommand CustomScanCommand { get; }
    public RelayCommand YaraCustomScanCommand { get; }
    public RelayCommand YaraQuickScanCommand { get; }

    public string TargetPath { get => _targetPath; set => SetProperty(ref _targetPath, value); }
    public string ScanOutput { get => _scanOutput; set => SetProperty(ref _scanOutput, value); }
    public string ScanResultText { get => _scanResultText; set => SetProperty(ref _scanResultText, value); }

    public bool IsScanning
    {
        get => _isScanning;
        set => SetProperty(ref _isScanning, value);
    }

    public string ElapsedText { get => _elapsedText; set => SetProperty(ref _elapsedText, value); }

    public bool HasExplainableResult => _lastOutcome is not null || _lastYaraReport is not null;

    public ScanMascotMood MascotMood { get => _mascotMood; set => SetProperty(ref _mascotMood, value); }

    public string MascotStatusText { get => _mascotStatusText; set => SetProperty(ref _mascotStatusText, value); }

    public bool IsAdministrator => _defender.IsElevated();

    public async Task RunYaraQuickScanAsync()
    {
        var targets = new List<string>();
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var downloads = Path.Combine(userProfile, "Downloads");
        var desktop = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
        var temp = Path.GetTempPath();
        if (Directory.Exists(downloads)) targets.Add(downloads);
        if (Directory.Exists(desktop)) targets.Add(desktop);
        if (Directory.Exists(temp)) targets.Add(temp);

        await RunYaraTargetsAsync(targets, "Quick Local YARA Scan (Downloads, Desktop, Temp)");
    }

    public async Task RunYaraScanAsync(string? targetPath)
    {
        if (string.IsNullOrWhiteSpace(targetPath))
        {
            ErrorMessage = "Choose a file or folder first to scan with the native YARA engine.";
            return;
        }

        await RunYaraTargetsAsync(new[] { targetPath.Trim() }, targetPath.Trim());
    }

    private async Task RunYaraTargetsAsync(IReadOnlyList<string> targets, string label)
    {
        if (IsScanning)
            return;

        IsScanning = true;
        ClearMessages();
        ScanOutput = string.Empty;
        ScanResultText = $"Running native YARA scan on {label}...";
        StatusMessage = "Local YARA engine scan in progress (real compiled .yar/.yara rules).";
        MascotMood = ScanMascotMood.Scanning;
        MascotStatusText = "Scanning now with the local native YARA engine...";
        _lastOutcome = null;
        _lastYaraReport = null;
        OnPropertyChanged(nameof(HasExplainableResult));

        using var elapsedCts = new CancellationTokenSource();
        var elapsedTask = TickElapsedAsync(elapsedCts.Token);

        try
        {
            var progress = new Progress<YaraScanProgress>(p =>
            {
                ScanResultText = $"YARA scanning: {p.FilesScanned} / {p.TotalFiles} file(s) · {p.MatchesFound} match(es)";
            });

            var result = await _yara.ScanTargetsAsync(targets, label, progress);
            if (!result.Success || result.Value is null)
            {
                ScanResultText = "YARA scan could not run.";
                ErrorMessage = result.Message;
                MascotMood = ScanMascotMood.Idle;
                MascotStatusText = "Resting — the YARA scan could not run.";
                await _events.RecordAsync("yara.scan.failed", result.Message, false, label);
                return;
            }

            var report = result.Value;
            _lastYaraReport = report;
            OnPropertyChanged(nameof(HasExplainableResult));
            ScanOutput = _yara.FormatReportAsText(report);
            ScanResultText = result.Message;

            if (report.ThreatFound)
            {
                MascotMood = ScanMascotMood.Alert;
                MascotStatusText = $"YARA detected {report.Matches.Count} match(es) — review the matched rules below.";
            }
            else
            {
                MascotMood = ScanMascotMood.Clean;
                MascotStatusText = $"All clear — Native YARA {report.EngineVersion} found 0 matches across {report.FilesScanned} file(s).";
            }

            _settings.Current.LastVerifiedScan = report.EndedAt;
            _settings.Current.LastScanSummary = report.ThreatFound
                ? $"YARA scan — {report.Matches.Count} rule match(es) found"
                : $"YARA scan — clean ({report.FilesScanned} files)";
            await _settings.SaveAsync();

            _sound.Play(report.ThreatFound ? SoundCue.Critical : SoundCue.ScanCompleted);

            if (report.ThreatFound)
            {
                await _notifications.NotifyCriticalAsync(
                    "BECETTI SECURITY — YARA threat found",
                    $"Native YARA matched rule '{report.Matches[0].RuleName}' ({report.Matches.Count} total match(es)).");
            }

            await _events.RecordAsync(
                report.ThreatFound ? "yara.scan.threat" : "yara.scan.completed",
                result.Message,
                true,
                $"YARA {report.EngineVersion}, Files={report.FilesScanned}, Matches={report.Matches.Count}");
        }
        finally
        {
            IsScanning = false;
            elapsedCts.Cancel();
            try { await elapsedTask; } catch (OperationCanceledException) { /* expected */ }
            ElapsedText = string.Empty;
        }
    }

    public async Task RunScanAsync(DefenderScanType scanType, string? targetPath = null)
    {
        if (IsScanning)
            return;

        IsScanning = true;
        ClearMessages();
        ScanOutput = string.Empty;
        ScanResultText = $"Running {scanType} scan...";
        StatusMessage = "Scan started. This may take a while; the result below comes from Microsoft Defender.";
        MascotMood = ScanMascotMood.Scanning;
        MascotStatusText = $"Scanning now ({scanType}) — this is a real Defender scan in progress.";
        _lastOutcome = null;
        _lastYaraReport = null;
        _lastScanType = scanType;
        OnPropertyChanged(nameof(HasExplainableResult));

        using var elapsedCts = new CancellationTokenSource();
        var elapsedTask = TickElapsedAsync(elapsedCts.Token);

        try
        {
            var result = await _defender.RunScanAsync(scanType, targetPath);
            if (!result.Success || result.Value is null)
            {
                ScanResultText = "Defender scan could not run. You can still scan locally using the Native YARA Engine above.";
                ErrorMessage = result.Message;
                MascotMood = ScanMascotMood.Idle;
                MascotStatusText = "Resting — Defender scan could not run (Native YARA Engine is available).";
                await _events.RecordAsync("scan.failed", $"{scanType} scan failed", false, result.Message);
                return;
            }

            var outcome = result.Value;
            ScanOutput = outcome.Output;
            ScanResultText = result.Message;
            _lastOutcome = outcome;
            OnPropertyChanged(nameof(HasExplainableResult));

            if (outcome.ThreatFound)
            {
                MascotMood = ScanMascotMood.Alert;
                MascotStatusText = "Threat detected — see the result below and Threat Management.";
            }
            else if (outcome.CompletedWithoutThreat)
            {
                MascotMood = ScanMascotMood.Clean;
                MascotStatusText = "All clear — Microsoft Defender found no threats.";
            }
            else
            {
                MascotMood = ScanMascotMood.Idle;
                MascotStatusText = "Resting — the scan ended with an unexpected result; see the output below.";
            }

            if (outcome.CompletedWithoutThreat || outcome.ThreatFound)
            {
                _settings.Current.LastVerifiedScan = outcome.EndedAt;
                _settings.Current.LastScanSummary = outcome.ThreatFound
                    ? $"{scanType} scan — threat found (see Threat Management)"
                    : $"{scanType} scan — no threats found";
                await _settings.SaveAsync();

                _sound.Play(outcome.ThreatFound ? SoundCue.Critical : SoundCue.ScanCompleted);

                if (outcome.ThreatFound)
                {
                    await _notifications.NotifyCriticalAsync(
                        "BECETTI SECURITY — threat found",
                        $"Microsoft Defender found a threat during a {scanType} scan. Open Threat Management to review it.");
                }
            }

            await _events.RecordAsync(
                outcome.ThreatFound ? "scan.threat" : "scan.completed",
                result.Message,
                outcome.CompletedWithoutThreat || outcome.ThreatFound,
                $"Exit code {outcome.ProcessExitCode}");
        }
        finally
        {
            IsScanning = false;
            elapsedCts.Cancel();
            try { await elapsedTask; } catch (OperationCanceledException) { /* expected */ }
            ElapsedText = string.Empty;
        }
    }

    private async Task TickElapsedAsync(CancellationToken ct)
    {
        var startedAt = DateTimeOffset.Now;
        try
        {
            while (!ct.IsCancellationRequested)
            {
                var elapsed = DateTimeOffset.Now - startedAt;
                ElapsedText = elapsed.TotalHours >= 1
                    ? $"{(int)elapsed.TotalHours:00}:{elapsed.Minutes:00}:{elapsed.Seconds:00} elapsed"
                    : $"{elapsed.Minutes:00}:{elapsed.Seconds:00} elapsed";
                await Task.Delay(TimeSpan.FromSeconds(1), ct).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
            // Expected when the scan finishes
        }
    }

    public string? BuildAiExplainPrompt()
    {
        if (_lastYaraReport is not null)
        {
            var r = _lastYaraReport;
            var lines = new List<string>
            {
                "Please explain this real local Native YARA Engine scan result from BECETTI SECURITY in plain language, and tell me if I need to do anything next:",
                $"- Engine: YARA {r.EngineVersion} (local Windows x64 engine)",
                $"- Target: {r.TargetPath}",
                $"- Files scanned: {r.FilesScanned}, Active rules: {r.TotalRulesLoaded}",
                $"- Matches found: {r.Matches.Count}"
            };
            foreach (var m in r.Matches.Take(8))
                lines.Add($"  * {m.RuleName} ({m.Severity}) on {m.FilePath}: {m.Description}");
            return string.Join("\n", lines);
        }

        if (_lastOutcome is null)
            return null;

        var o = _lastOutcome;
        return "Please explain this real Microsoft Defender scan result from BECETTI SECURITY's Smart Scan in plain language, and tell me if I need to do anything next:\n" +
               $"- Scan type: {_lastScanType}\n" +
               (string.IsNullOrWhiteSpace(o.TargetPath) ? string.Empty : $"- Target: {o.TargetPath}\n") +
               $"- Started: {o.StartedAt:u}, ended: {o.EndedAt:u}\n" +
               $"- Defender process exit code: {o.ProcessExitCode}\n" +
               $"- Threat found: {o.ThreatFound}\n" +
               $"- Completed without threat: {o.CompletedWithoutThreat}\n" +
               (string.IsNullOrWhiteSpace(o.Error) ? string.Empty : $"- Error: {o.Error}\n");
    }
}
