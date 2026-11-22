using System.Collections.ObjectModel;
using Becetti.Security.App.Services;
using Becetti.Security.Core.Models;
using Becetti.Security.Core.Services;

namespace Becetti.Security.App.ViewModels;

/// <summary>
/// Native YARA Engine page: local file/folder malware scanning, real-time progress,
/// detailed matched-rule reports, .yar/.yara rule validation &amp; management, and
/// trusted repository updates. Never simulates results.
/// </summary>
public sealed class YaraScannerViewModel : ViewModelBase
{
    private readonly IYaraEngineService _yara;
    private readonly IEventLogService _events;
    private readonly ISettingsService _settings;
    private readonly SoundService _sound;
    private readonly NotificationService _notifications;

    private CancellationTokenSource? _scanCts;
    private YaraEngineInfo? _engineInfo;
    private YaraScanReport? _lastReport;

    private string _engineStatusText = "Checking native YARA engine...";
    private string _engineDetailText = string.Empty;
    private string _licenseNoticeText = "Powered by YARA (https://github.com/VirusTotal/yara) — Copyright (c) 2007-2016 The YARA Authors. Licensed under the BSD 3-Clause License.";
    private bool _isEngineAvailable;
    private string _targetPath = string.Empty;
    private bool _isScanning;
    private double _progressPercent;
    private string _progressText = string.Empty;
    private string _currentFileText = string.Empty;
    private string _verdictText = "No YARA scan run yet.";
    private string _reportSummaryText = string.Empty;
    private string _customRuleUrl = string.Empty;
    private string _ruleUpdateSummary = string.Empty;
    private YaraTrustedRepository? _selectedRepository;

    public YaraScannerViewModel(
        IYaraEngineService yara,
        IEventLogService events,
        ISettingsService settings,
        SoundService sound,
        NotificationService notifications)
    {
        _yara = yara;
        _events = events;
        _settings = settings;
        _sound = sound;
        _notifications = notifications;

        foreach (var repo in _yara.TrustedRepositories)
            TrustedRepositories.Add(repo);
        _selectedRepository = TrustedRepositories.FirstOrDefault();

        RefreshEngineCommand = new RelayCommand(InitializeAsync);
        RebuildRulesCommand = new RelayCommand(RebuildRulesAsync);
        ScanTargetCommand = new RelayCommand(ScanTargetAsync, () => !IsScanning);
        QuickLocalScanCommand = new RelayCommand(QuickLocalScanAsync, () => !IsScanning);
        CancelScanCommand = new RelayCommand(CancelScanAsync, () => IsScanning);
        UpdateFromRepositoryCommand = new RelayCommand(UpdateFromSelectedRepositoryAsync);
        UpdateFromCustomUrlCommand = new RelayCommand(UpdateFromCustomUrlAsync);
    }

    public ObservableCollection<YaraRuleFileInfo> RuleFiles { get; } = new();
    public ObservableCollection<YaraRuleMatch> Matches { get; } = new();
    public ObservableCollection<YaraScanError> ScanErrors { get; } = new();
    public ObservableCollection<YaraTrustedRepository> TrustedRepositories { get; } = new();

    public RelayCommand RefreshEngineCommand { get; }
    public RelayCommand RebuildRulesCommand { get; }
    public RelayCommand ScanTargetCommand { get; }
    public RelayCommand QuickLocalScanCommand { get; }
    public RelayCommand CancelScanCommand { get; }
    public RelayCommand UpdateFromRepositoryCommand { get; }
    public RelayCommand UpdateFromCustomUrlCommand { get; }

    public bool IsEngineAvailable { get => _isEngineAvailable; private set => SetProperty(ref _isEngineAvailable, value); }
    public string EngineStatusText { get => _engineStatusText; private set => SetProperty(ref _engineStatusText, value); }
    public string EngineDetailText { get => _engineDetailText; private set => SetProperty(ref _engineDetailText, value); }
    public string LicenseNoticeText { get => _licenseNoticeText; private set => SetProperty(ref _licenseNoticeText, value); }

    public string TargetPath { get => _targetPath; set => SetProperty(ref _targetPath, value); }
    public string CustomRuleUrl { get => _customRuleUrl; set => SetProperty(ref _customRuleUrl, value); }
    public string RuleUpdateSummary { get => _ruleUpdateSummary; private set => SetProperty(ref _ruleUpdateSummary, value); }

    public YaraTrustedRepository? SelectedRepository
    {
        get => _selectedRepository;
        set => SetProperty(ref _selectedRepository, value);
    }

    public bool IsScanning
    {
        get => _isScanning;
        private set
        {
            if (SetProperty(ref _isScanning, value))
            {
                ScanTargetCommand.RaiseCanExecuteChanged();
                QuickLocalScanCommand.RaiseCanExecuteChanged();
                CancelScanCommand.RaiseCanExecuteChanged();
            }
        }
    }

    public double ProgressPercent { get => _progressPercent; private set => SetProperty(ref _progressPercent, value); }
    public string ProgressText { get => _progressText; private set => SetProperty(ref _progressText, value); }
    public string CurrentFileText { get => _currentFileText; private set => SetProperty(ref _currentFileText, value); }
    public string VerdictText { get => _verdictText; private set => SetProperty(ref _verdictText, value); }
    public string ReportSummaryText { get => _reportSummaryText; private set => SetProperty(ref _reportSummaryText, value); }
    public bool HasReport => _lastReport is not null;
    public bool HasMatches => Matches.Count > 0;
    public bool HasScanErrors => ScanErrors.Count > 0;
    public YaraScanReport? LastReport => _lastReport;

    public async Task InitializeAsync()
    {
        if (IsBusy)
            return;

        IsBusy = true;
        ClearMessages();
        try
        {
            var result = await _yara.InitializeAsync();
            if (result.Success && result.Value is not null)
            {
                ApplyEngineInfo(result.Value);
                StatusMessage = result.Message;
            }
            else
            {
                var infoResult = await _yara.GetEngineInfoAsync();
                if (infoResult.Value is not null)
                    ApplyEngineInfo(infoResult.Value);
                else
                {
                    IsEngineAvailable = false;
                    EngineStatusText = "Native YARA engine unavailable";
                    EngineDetailText = result.Message;
                }
                ErrorMessage = result.Message;
            }

            await ReloadRuleFilesAsync();
        }
        finally
        {
            IsBusy = false;
        }
    }

    public async Task RebuildRulesAsync()
    {
        if (IsBusy || IsScanning)
            return;

        IsBusy = true;
        ClearMessages();
        try
        {
            var result = await _yara.RebuildCompiledRulesAsync();
            if (result.Success && result.Value is not null)
            {
                ApplyEngineInfo(result.Value);
                StatusMessage = result.Message;
            }
            else
            {
                ErrorMessage = result.Message;
            }

            await ReloadRuleFilesAsync();
        }
        finally
        {
            IsBusy = false;
        }
    }

    public async Task ImportRuleFileAsync(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || IsBusy || IsScanning)
            return;

        IsBusy = true;
        ClearMessages();
        try
        {
            var result = await _yara.ImportRuleFileAsync(path);
            if (result.Success && result.Value is not null)
            {
                StatusMessage = result.Message;
                await _events.RecordAsync("yara.rule.imported", result.Message, true, result.Value.FileName);
            }
            else
            {
                ErrorMessage = result.Message;
                await _events.RecordAsync("yara.rule.rejected", result.Message, false, path);
            }

            var info = await _yara.GetEngineInfoAsync();
            if (info.Value is not null)
                ApplyEngineInfo(info.Value);
            await ReloadRuleFilesAsync();
        }
        finally
        {
            IsBusy = false;
        }
    }

    public async Task ToggleRuleEnabledAsync(YaraRuleFileInfo rule)
    {
        if (IsBusy || IsScanning)
            return;

        IsBusy = true;
        ClearMessages();
        try
        {
            var newEnabled = !rule.IsEnabled;
            var result = await _yara.SetRuleEnabledAsync(rule.Id, newEnabled);
            if (result.Success && result.Value is not null)
            {
                ApplyEngineInfo(result.Value);
                StatusMessage = $"{rule.FileName} {(newEnabled ? "enabled" : "disabled")}. {result.Message}";
            }
            else
            {
                ErrorMessage = result.Message;
            }
            await ReloadRuleFilesAsync();
        }
        finally
        {
            IsBusy = false;
        }
    }

    public async Task RemoveRuleFileAsync(YaraRuleFileInfo rule)
    {
        if (IsBusy || IsScanning || !rule.CanDelete)
            return;

        IsBusy = true;
        ClearMessages();
        try
        {
            var result = await _yara.RemoveRuleFileAsync(rule.Id);
            if (result.Success && result.Value is not null)
            {
                ApplyEngineInfo(result.Value);
                StatusMessage = $"Removed {rule.FileName}. {result.Message}";
            }
            else
            {
                ErrorMessage = result.Message;
            }
            await ReloadRuleFilesAsync();
        }
        finally
        {
            IsBusy = false;
        }
    }

    public async Task ScanTargetAsync()
    {
        if (string.IsNullOrWhiteSpace(TargetPath))
        {
            ErrorMessage = "Choose a file or folder to scan with the native YARA engine.";
            return;
        }

        await ExecuteScanAsync(new[] { TargetPath.Trim() }, TargetPath.Trim());
    }

    public async Task QuickLocalScanAsync()
    {
        var targets = new List<string>();
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var downloads = Path.Combine(userProfile, "Downloads");
        var desktop = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
        var temp = Path.GetTempPath();

        if (Directory.Exists(downloads)) targets.Add(downloads);
        if (Directory.Exists(desktop)) targets.Add(desktop);
        if (Directory.Exists(temp)) targets.Add(temp);

        if (targets.Count == 0)
        {
            ErrorMessage = "No standard user folders (Downloads, Desktop, Temp) were found.";
            return;
        }

        await ExecuteScanAsync(targets, "Quick Local Scan (Downloads, Desktop, Temp)");
    }

    private async Task ExecuteScanAsync(IReadOnlyList<string> targets, string label)
    {
        if (IsScanning)
            return;

        IsScanning = true;
        ClearMessages();
        Matches.Clear();
        ScanErrors.Clear();
        OnPropertyChanged(nameof(HasMatches));
        OnPropertyChanged(nameof(HasScanErrors));
        _lastReport = null;
        OnPropertyChanged(nameof(HasReport));

        ProgressPercent = 0;
        ProgressText = "Preparing native YARA scan...";
        CurrentFileText = label;
        VerdictText = "Scanning with local native YARA engine...";
        ReportSummaryText = string.Empty;

        _scanCts = new CancellationTokenSource();
        var progress = new Progress<YaraScanProgress>(p =>
        {
            ProgressPercent = p.PercentComplete;
            ProgressText = $"{p.FilesScanned} / {p.TotalFiles} file(s) · {p.MatchesFound} match(es) · {p.ErrorsCount} error(s) · {p.Elapsed.TotalSeconds:F1}s";
            CurrentFileText = p.CurrentFile;
        });

        try
        {
            var result = await _yara.ScanTargetsAsync(targets, label, progress, _scanCts.Token);
            if (!result.Success || result.Value is null)
            {
                VerdictText = "YARA scan could not run.";
                ErrorMessage = result.Message;
                await _events.RecordAsync("yara.scan.failed", result.Message, false, label);
                return;
            }

            var report = result.Value;
            _lastReport = report;
            OnPropertyChanged(nameof(HasReport));

            foreach (var match in report.Matches)
                Matches.Add(match);
            foreach (var err in report.Errors)
                ScanErrors.Add(err);
            OnPropertyChanged(nameof(HasMatches));
            OnPropertyChanged(nameof(HasScanErrors));

            ProgressPercent = report.WasCancelled ? ProgressPercent : 100;
            VerdictText = report.WasCancelled
                ? $"Scan cancelled — {report.Matches.Count} match(es) found before cancellation."
                : report.ThreatFound
                    ? $"DETECTIONS FOUND: {report.Matches.Count} YARA rule match(es) in {report.FilesScanned} file(s)."
                    : $"CLEAN: 0 YARA rule matches across {report.FilesScanned} file(s).";

            ReportSummaryText =
                $"Scan ID {report.ScanId} · YARA {report.EngineVersion} · {report.TotalRulesLoaded} active rules · " +
                $"{report.FilesScanned} scanned, {report.FilesSkipped} skipped · {report.Duration.TotalSeconds:F2}s";
            StatusMessage = result.Message;

            if (!report.WasCancelled)
            {
                _settings.Current.LastVerifiedScan = report.EndedAt;
                _settings.Current.LastScanSummary = report.ThreatFound
                    ? $"YARA scan — {report.Matches.Count} match(es) detected"
                    : $"YARA scan — clean ({report.FilesScanned} files)";
                await _settings.SaveAsync();

                _sound.Play(report.ThreatFound ? SoundCue.Critical : SoundCue.ScanCompleted);

                if (report.ThreatFound)
                {
                    var topRule = report.Matches[0].RuleName;
                    await _notifications.NotifyCriticalAsync(
                        "BECETTI SECURITY — YARA threat detected",
                        $"Native YARA engine matched rule '{topRule}' ({report.Matches.Count} total match(es)). Review YARA Engine report.");
                }
            }

            await _events.RecordAsync(
                report.ThreatFound ? "yara.scan.threat" : "yara.scan.completed",
                result.Message,
                !report.WasCancelled,
                $"Files={report.FilesScanned}, Matches={report.Matches.Count}, Errors={report.Errors.Count}");
        }
        finally
        {
            IsScanning = false;
            _scanCts?.Dispose();
            _scanCts = null;
        }
    }

    private Task CancelScanAsync()
    {
        _scanCts?.Cancel();
        StatusMessage = "Cancelling YARA scan...";
        return Task.CompletedTask;
    }

    public async Task UpdateFromSelectedRepositoryAsync()
    {
        if (SelectedRepository is null || IsBusy || IsScanning)
            return;

        IsBusy = true;
        ClearMessages();
        RuleUpdateSummary = $"Downloading and validating rules from {SelectedRepository.Name}...";
        try
        {
            var result = await _yara.UpdateRulesFromRepositoryAsync(SelectedRepository.Id);
            ApplyRuleUpdateResult(result);
            await RefreshAfterRuleChangeAsync();
        }
        finally
        {
            IsBusy = false;
        }
    }

    public async Task UpdateFromCustomUrlAsync()
    {
        if (string.IsNullOrWhiteSpace(CustomRuleUrl) || IsBusy || IsScanning)
        {
            ErrorMessage = "Enter a trusted HTTPS URL ending in .yar or .yara.";
            return;
        }

        IsBusy = true;
        ClearMessages();
        RuleUpdateSummary = "Downloading and validating remote rule file with yarac64...";
        try
        {
            var result = await _yara.UpdateRuleFromHttpsUrlAsync(CustomRuleUrl.Trim());
            ApplyRuleUpdateResult(result);
            if (result.Success)
                CustomRuleUrl = string.Empty;
            await RefreshAfterRuleChangeAsync();
        }
        finally
        {
            IsBusy = false;
        }
    }

    private void ApplyRuleUpdateResult(OperationResult<YaraRuleUpdateResult> result)
    {
        if (result.Success && result.Value is not null)
        {
            var u = result.Value;
            StatusMessage = result.Message;
            var details = new List<string>
            {
                $"Source: {u.SourceName}",
                $"Validated & Activated: {u.ValidatedAndImportedCount} / {u.AttemptedCount}",
                $"Rejected (kept out of scanner): {u.RejectedCount}"
            };
            foreach (var rejected in u.RejectedFiles.Take(6))
                details.Add($"  • Rejected {rejected.Key}: {rejected.Value}");
            RuleUpdateSummary = string.Join(Environment.NewLine, details);
        }
        else
        {
            ErrorMessage = result.Message;
            RuleUpdateSummary = result.Message;
        }
    }

    private async Task RefreshAfterRuleChangeAsync()
    {
        var info = await _yara.GetEngineInfoAsync();
        if (info.Value is not null)
            ApplyEngineInfo(info.Value);
        await ReloadRuleFilesAsync();
    }

    private async Task ReloadRuleFilesAsync()
    {
        var filesResult = await _yara.GetRuleFilesAsync();
        RuleFiles.Clear();
        if (filesResult.Success && filesResult.Value is not null)
        {
            foreach (var rf in filesResult.Value)
                RuleFiles.Add(rf);
        }
    }

    private void ApplyEngineInfo(YaraEngineInfo info)
    {
        _engineInfo = info;
        IsEngineAvailable = info.IsAvailable;
        LicenseNoticeText = info.LicenseNotice;

        if (info.IsAvailable)
        {
            EngineStatusText = $"Native YARA {info.Version} ({info.Architecture}) — Active";
            EngineDetailText =
                $"Compiled rule files: {info.ValidRuleFiles} valid ({info.ActiveRuleCount} rules), " +
                $"{info.InvalidRuleFiles} invalid (isolated), {info.DisabledRuleFiles} disabled." +
                (string.IsNullOrWhiteSpace(info.BuildOrigin) ? string.Empty : $" · {info.BuildOrigin}");
        }
        else
        {
            EngineStatusText = "Native YARA engine binaries not found";
            EngineDetailText = info.Error ?? "yara64.exe / yarac64.exe not present.";
        }
    }

    public string? GetTextReport() => _lastReport is null ? null : _yara.FormatReportAsText(_lastReport);
    public string? GetJsonReport() => _lastReport is null ? null : _yara.FormatReportAsJson(_lastReport);

    public byte[]? GetPdfReportBytes() =>
        _lastReport is null ? null : _yara.FormatReportAsPdf(_lastReport);

    public string? BuildAiExplainPrompt()
    {
        if (_lastReport is null)
            return null;

        var r = _lastReport;
        var lines = new List<string>
        {
            "Please explain this real local Native YARA Engine scan report from BECETTI SECURITY in plain language, and tell me what action I should take:",
            $"- Engine: YARA {r.EngineVersion} (local Windows x64 engine)",
            $"- Target: {r.TargetPath}",
            $"- Files scanned: {r.FilesScanned}, skipped: {r.FilesSkipped}",
            $"- Active YARA rules loaded: {r.TotalRulesLoaded}",
            $"- Total matches: {r.Matches.Count}"
        };

        foreach (var m in r.Matches.Take(10))
            lines.Add($"  * Rule '{m.RuleName}' ({m.Severity}) on '{m.FilePath}': {m.Description}");

        if (r.Errors.Count > 0)
            lines.Add($"- Scan errors: {r.Errors.Count} (e.g. {r.Errors[0].DisplayLine})");

        return string.Join("\n", lines);
    }
}
