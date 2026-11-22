using Becetti.Security.App.Services;
using Becetti.Security.Core.Models;
using Becetti.Security.Core.Services;

namespace Becetti.Security.App.ViewModels;

/// <summary>
/// Visual state of the robot mascot on the Scan page. Every value here is
/// driven directly by a real Defender scan state (IsScanning / the real
/// MpCmdRun exit code) - never decorative or guessed, matching this app's
/// standing rule that nothing ever fakes activity that isn't happening.
/// </summary>
public enum ScanMascotMood
{
    /// <summary>No scan is running and the last one (if any) is not being shown.</summary>
    Idle,
    /// <summary>A real Defender scan is currently in progress.</summary>
    Scanning,
    /// <summary>The last real scan completed with no threat found (MpCmdRun exit code 0).</summary>
    Clean,
    /// <summary>The last real scan found a threat (MpCmdRun exit code 2).</summary>
    Alert
}

/// <summary>
/// Smart Scan page. Scans run through Microsoft Defender (MpCmdRun.exe).
/// Results come from Defender's exit codes — BECETTI SECURITY never declares
/// a file infected on its own.
/// </summary>
public sealed class ScanViewModel : ViewModelBase
{
    private readonly IDefenderService _defender;
    private readonly IEventLogService _events;
    private readonly ISettingsService _settings;
    private readonly SoundService _sound;

    private string _targetPath = string.Empty;
    private string _scanOutput = string.Empty;
    private string _scanResultText = "No scan started yet.";
    private bool _isScanning;
    private ScanMascotMood _mascotMood = ScanMascotMood.Idle;
    private string _mascotStatusText = "Resting — no scan running right now.";
    private string _elapsedText = string.Empty;
    private ScanOutcome? _lastOutcome;
    private DefenderScanType _lastScanType;

    public ScanViewModel(IDefenderService defender, IEventLogService events, ISettingsService settings, SoundService sound)
    {
        _defender = defender;
        _events = events;
        _settings = settings;
        _sound = sound;
        QuickScanCommand = new RelayCommand(() => RunScanAsync(DefenderScanType.Quick));
        FullScanCommand = new RelayCommand(() => RunScanAsync(DefenderScanType.Full));
        CustomScanCommand = new RelayCommand(() => RunScanAsync(DefenderScanType.Custom, TargetPath));
    }

    public RelayCommand QuickScanCommand { get; }
    public RelayCommand FullScanCommand { get; }
    public RelayCommand CustomScanCommand { get; }

    public string TargetPath { get => _targetPath; set => SetProperty(ref _targetPath, value); }
    public string ScanOutput { get => _scanOutput; set => SetProperty(ref _scanOutput, value); }
    public string ScanResultText { get => _scanResultText; set => SetProperty(ref _scanResultText, value); }

    public bool IsScanning
    {
        get => _isScanning;
        set => SetProperty(ref _isScanning, value);
    }

    /// <summary>
    /// Real elapsed time since the running scan started, ticking once a second.
    /// MpCmdRun.exe reports no percentage-complete while it runs, so a fabricated
    /// progress bar would be a fake number — elapsed time is the only "progress"
    /// BECETTI SECURITY can show honestly while Defender is still working.
    /// </summary>
    public string ElapsedText { get => _elapsedText; set => SetProperty(ref _elapsedText, value); }

    /// <summary>True once a scan has actually completed (clean or threat found) and can be explained.</summary>
    public bool HasExplainableResult => _lastOutcome is not null;

    /// <summary>Drives the robot mascot's glow color and pulse animation on the Scan page.</summary>
    public ScanMascotMood MascotMood { get => _mascotMood; set => SetProperty(ref _mascotMood, value); }

    /// <summary>Human-readable text shown next to the mascot, matching <see cref="MascotMood"/>.</summary>
    public string MascotStatusText { get => _mascotStatusText; set => SetProperty(ref _mascotStatusText, value); }

    public bool IsAdministrator => _defender.IsElevated();

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
        _lastScanType = scanType;
        OnPropertyChanged(nameof(HasExplainableResult));

        using var elapsedCts = new CancellationTokenSource();
        var elapsedTask = TickElapsedAsync(elapsedCts.Token);

        try
        {
            var result = await _defender.RunScanAsync(scanType, targetPath);
            if (!result.Success || result.Value is null)
            {
                ScanResultText = "Scan could not run.";
                ErrorMessage = result.Message;
                MascotMood = ScanMascotMood.Idle;
                MascotStatusText = "Resting — the last scan could not run.";
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

    /// <summary>Ticks ElapsedText once a second while a scan is running. Real wall-clock time only.</summary>
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
            // Expected when the scan finishes; ElapsedText is cleared by the caller.
        }
    }

    /// <summary>
    /// Builds a plain-text prompt from the last real scan outcome for BECETTI AI to
    /// explain — every field comes straight from Defender's own MpCmdRun result, never
    /// invented. Returns null until a scan has actually completed.
    /// </summary>
    public string? BuildAiExplainPrompt()
    {
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
