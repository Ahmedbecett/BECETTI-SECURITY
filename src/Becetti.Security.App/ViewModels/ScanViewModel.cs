using Becetti.Security.Core.Models;
using Becetti.Security.Core.Services;

namespace Becetti.Security.App.ViewModels;

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

    private string _targetPath = string.Empty;
    private string _scanOutput = string.Empty;
    private string _scanResultText = "No scan started yet.";
    private bool _isScanning;

    public ScanViewModel(IDefenderService defender, IEventLogService events, ISettingsService settings)
    {
        _defender = defender;
        _events = events;
        _settings = settings;
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

        try
        {
            var result = await _defender.RunScanAsync(scanType, targetPath);
            if (!result.Success || result.Value is null)
            {
                ScanResultText = "Scan could not run.";
                ErrorMessage = result.Message;
                await _events.RecordAsync("scan.failed", $"{scanType} scan failed", false, result.Message);
                return;
            }

            var outcome = result.Value;
            ScanOutput = outcome.Output;
            ScanResultText = result.Message;

            if (outcome.CompletedWithoutThreat || outcome.ThreatFound)
            {
                _settings.Current.LastVerifiedScan = outcome.EndedAt;
                _settings.Current.LastScanSummary = outcome.ThreatFound
                    ? $"{scanType} scan — threat found (see Threat Management)"
                    : $"{scanType} scan — no threats found";
                await _settings.SaveAsync();
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
        }
    }
}
