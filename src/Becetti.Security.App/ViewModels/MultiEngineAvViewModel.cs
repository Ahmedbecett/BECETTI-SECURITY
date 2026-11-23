using System.Collections.ObjectModel;
using System.Windows.Input;
using Becetti.Security.App.Services;
using Becetti.Security.Core.Models;
using Becetti.Security.Core.Services;

namespace Becetti.Security.App.ViewModels;

/// <summary>
/// 5-Engine Open-Source &amp; Local Multi-AV Consensus Hub ViewModel:
/// Microsoft Defender + Native YARA v4.6.0 (43 rules) + Cisco Talos ClamAV +
/// VirusTotal YARA-X (Rust) + Mandiant CAPA (ATT&amp;CK Behavior Analyzer).
/// Zero API keys, zero cloud uploads, 1-Click official GitHub installer.
/// </summary>
public sealed class MultiEngineAvViewModel : ViewModelBase
{
    private readonly IMultiEngineAvService _av;
    private readonly IQuarantineService _quarantine;
    private readonly IAiTriageNavigator _aiTriage;

    private string _enginesSummary = "Inspecting local open-source antivirus engines…";
    private string _targetPath = string.Empty;
    private string _consensusVerdict = "Ready — Select any file or folder to scan across all installed engines.";
    private string _targetSha256 = "—";
    private MultiEngineScanReport? _lastReport;

    public MultiEngineAvViewModel(
        IMultiEngineAvService av,
        IQuarantineService quarantine,
        IAiTriageNavigator aiTriage)
    {
        _av = av;
        _quarantine = quarantine;
        _aiTriage = aiTriage;

        RefreshEnginesCommand = new RelayCommand(RefreshEnginesAsync);
        InstallClamAvCommand = new RelayCommand(() => InstallEngineAsync("clamav"));
        UpdateClamAvDbCommand = new RelayCommand(UpdateClamAvDbAsync);
        InstallYaraXCommand = new RelayCommand(() => InstallEngineAsync("yarax"));
        InstallCapaCommand = new RelayCommand(() => InstallEngineAsync("capa"));
        ScanAllEnginesCommand = new RelayCommand(ScanTargetAsync);
        QuarantineTargetCommand = new RelayCommand(QuarantineTargetAsync);
        AskAiAboutResultCommand = new RelayCommand(() => { AskAiAboutResult(); return Task.CompletedTask; });
    }

    public ObservableCollection<AvEngineInfo> Engines { get; } = new();
    public ObservableCollection<SingleEngineVerdict> ScanVerdicts { get; } = new();
    public ObservableCollection<string> CapaCapabilities { get; } = new();

    public ICommand RefreshEnginesCommand { get; }
    public ICommand InstallClamAvCommand { get; }
    public ICommand UpdateClamAvDbCommand { get; }
    public ICommand InstallYaraXCommand { get; }
    public ICommand InstallCapaCommand { get; }
    public ICommand ScanAllEnginesCommand { get; }
    public ICommand QuarantineTargetCommand { get; }
    public ICommand AskAiAboutResultCommand { get; }

    public string EnginesSummary { get => _enginesSummary; set => SetProperty(ref _enginesSummary, value); }
    public string TargetPath { get => _targetPath; set => SetProperty(ref _targetPath, value); }
    public string ConsensusVerdict { get => _consensusVerdict; set => SetProperty(ref _consensusVerdict, value); }
    public string TargetSha256 { get => _targetSha256; set => SetProperty(ref _targetSha256, value); }

    public async Task RefreshEnginesAsync()
    {
        if (IsBusy) return;
        IsBusy = true; ClearMessages();
        try
        {
            var res = await _av.GetEnginesStatusAsync();
            if (!res.Success || res.Value is null) { ErrorMessage = res.Message; return; }
            Engines.Clear();
            foreach (var e in res.Value) Engines.Add(e);
            EnginesSummary = res.Message;
        }
        finally { IsBusy = false; }
    }

    public async Task InstallEngineAsync(string engineId)
    {
        if (IsBusy) return;
        IsBusy = true; ClearMessages();
        try
        {
            var progress = new Progress<string>(msg => StatusMessage = msg);
            var res = await _av.InstallOrUpdateOpenSourceEngineAsync(engineId, progress);
            if (!res.Success) { ErrorMessage = res.Message; return; }
            StatusMessage = res.Message;

            var refresh = await _av.GetEnginesStatusAsync();
            if (refresh.Success && refresh.Value is not null)
            {
                Engines.Clear();
                foreach (var e in refresh.Value) Engines.Add(e);
                EnginesSummary = refresh.Message;
            }
        }
        finally { IsBusy = false; }
    }

    public async Task UpdateClamAvDbAsync()
    {
        if (IsBusy) return;
        IsBusy = true; ClearMessages();
        try
        {
            StatusMessage = "Running official ClamAV freshclam.exe to download latest CVD virus definitions…";
            var res = await _av.UpdateClamAvSignaturesAsync();
            if (res.Success) StatusMessage = res.Message; else ErrorMessage = res.Message;

            var refresh = await _av.GetEnginesStatusAsync();
            if (refresh.Success && refresh.Value is not null)
            {
                Engines.Clear();
                foreach (var e in refresh.Value) Engines.Add(e);
                EnginesSummary = refresh.Message;
            }
        }
        finally { IsBusy = false; }
    }

    public async Task ScanTargetAsync()
    {
        if (IsBusy) return;
        if (string.IsNullOrWhiteSpace(TargetPath))
        {
            ErrorMessage = "Pick a file or folder first before launching the Multi-Engine Consensus Scan.";
            return;
        }

        IsBusy = true; ClearMessages();
        try
        {
            StatusMessage = "Scanning target concurrently across all ready local open-source engines…";
            var res = await _av.ScanTargetWithAllEnginesAsync(TargetPath);
            if (!res.Success || res.Value is null) { ErrorMessage = res.Message; return; }

            _lastReport = res.Value;
            ConsensusVerdict = res.Value.Summary;
            TargetSha256 = $"SHA-256: {res.Value.TargetSha256}";

            ScanVerdicts.Clear();
            foreach (var v in res.Value.EngineResults) ScanVerdicts.Add(v);

            CapaCapabilities.Clear();
            foreach (var c in res.Value.CapaCapabilities) CapaCapabilities.Add(c);

            StatusMessage = res.Message;
        }
        finally { IsBusy = false; }
    }

    public async Task QuarantineTargetAsync()
    {
        if (IsBusy) return;
        if (string.IsNullOrWhiteSpace(TargetPath) || !File.Exists(TargetPath))
        {
            ErrorMessage = "Select a single file to isolate into AES-256-GCM Quarantine.";
            return;
        }
        IsBusy = true; ClearMessages();
        try
        {
            var reason = _lastReport?.OverallVerdict ?? "Multi-Engine AV Quarantine";
            var res = await _quarantine.QuarantineFileAsync(TargetPath, "MultiEngine_Detection", reason, "Multi-AV");
            if (res.Success) StatusMessage = res.Message; else ErrorMessage = res.Message;
        }
        finally { IsBusy = false; }
    }

    private void AskAiAboutResult()
    {
        if (_lastReport is null) return;
        var lines = string.Join("\n", _lastReport.EngineResults.Select(r => "- " + r.DisplayLine));
        _aiTriage.SendToBecettiAi(
            $"Analyze this Multi-Engine Local Antivirus Consensus Scan from BECETTI SECURITY:\n" +
            $"Target: {_lastReport.TargetPath}\nSHA-256: {_lastReport.TargetSha256}\n" +
            $"Overall Verdict: {_lastReport.OverallVerdict}\nEngine Results:\n{lines}\n" +
            $"Explain the findings and recommend safe remediation steps.");
    }
}
