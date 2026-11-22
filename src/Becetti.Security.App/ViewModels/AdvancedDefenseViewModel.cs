using System.Collections.ObjectModel;
using Becetti.Security.Core.Models;
using Becetti.Security.Core.Services;

namespace Becetti.Security.App.ViewModels;

/// <summary>
/// ViewModel for Advanced Defense &amp; Forensics Center:
/// Real-Time YARA Folder Guard, AES-256-GCM Quarantine Vault, Live Process Memory YARA Scanner,
/// Static PE/Entropy/Authenticode Analyzer + AI Threat Investigator, Ransomware Canary Honeypot,
/// Clipboard Hijack Guard, USB Auto-Scan, Scheduled YARA Auto-Updates, and Explorer Context Menu.
/// </summary>
public sealed class AdvancedDefenseViewModel : ViewModelBase
{
    private readonly IRealTimeYaraGuardService _folderGuard;
    private readonly IQuarantineService _quarantine;
    private readonly IYaraEngineService _yara;
    private readonly IFileForensicsService _forensics;
    private readonly IRansomwareCanaryService _canary;
    private readonly IClipboardGuardService _clipboardGuard;
    private readonly IUsbAutoScanService _usbAutoScan;
    private readonly IScheduledYaraUpdateService _scheduledYara;
    private readonly IExplorerContextMenuService _contextMenu;
    private readonly ISettingsService _settings;
    private readonly LocalizationService _localization;

    private CancellationTokenSource? _procScanCts;
    private bool _isLoading;

    private bool _folderGuardEnabled;
    private bool _autoQuarantineEnabled;
    private string _folderGuardStatus = "Stopped";

    private string _targetPidText = string.Empty;
    private bool _isScanningProcesses;
    private double _procScanPercent;
    private string _procScanStatus = "Ready to scan running processes in memory via yara64.exe.";

    private string _forensicsFilePath = string.Empty;
    private FileForensicsReport? _currentForensics;
    private string _forensicsSummary = "Select any executable (.exe/.dll) or file to inspect SHA-256, Shannon entropy, Authenticode signature, PE sections, and sensitive APIs.";

    private bool _canaryEnabled;
    private string _canaryStatus = "Disarmed";

    private bool _clipboardGuardEnabled;
    private string _clipboardStatus = "Inactive";

    private bool _usbAutoScanEnabled;
    private string _usbStatus = "Inactive";

    private bool _scheduledYaraEnabled;
    private double _scheduledIntervalHours = 24;
    private string _scheduledYaraStatus = "Not run yet";

    private bool _contextMenuRegistered;
    private string _contextMenuStatus = "Not registered";

    public AdvancedDefenseViewModel(
        IRealTimeYaraGuardService folderGuard,
        IQuarantineService quarantine,
        IYaraEngineService yara,
        IFileForensicsService forensics,
        IRansomwareCanaryService canary,
        IClipboardGuardService clipboardGuard,
        IUsbAutoScanService usbAutoScan,
        IScheduledYaraUpdateService scheduledYara,
        IExplorerContextMenuService contextMenu,
        ISettingsService settings,
        LocalizationService localization)
    {
        _folderGuard = folderGuard;
        _quarantine = quarantine;
        _yara = yara;
        _forensics = forensics;
        _canary = canary;
        _clipboardGuard = clipboardGuard;
        _usbAutoScan = usbAutoScan;
        _scheduledYara = scheduledYara;
        _contextMenu = contextMenu;
        _settings = settings;
        _localization = localization;

        LoadCommand = new RelayCommand(LoadAsync);
        RefreshQuarantineCommand = new RelayCommand(RefreshQuarantineAsync);
        ScanAllProcessesCommand = new RelayCommand(ScanAllProcessesAsync, () => !IsScanningProcesses);
        ScanSinglePidCommand = new RelayCommand(ScanSinglePidAsync, () => !IsScanningProcesses && int.TryParse(TargetPidText.Trim(), out var pid) && pid > 4);
        CancelProcessScanCommand = new RelayCommand(() => { CancelProcessScan(); return Task.CompletedTask; }, () => IsScanningProcesses);
        AnalyzeForensicsCommand = new RelayCommand(AnalyzeForensicsAsync, () => !string.IsNullOrWhiteSpace(ForensicsFilePath));
        InvestigateForensicsWithAiCommand = new RelayCommand(() => { InvestigateForensicsWithAi(); return Task.CompletedTask; }, () => CurrentForensics is not null);
        VerifyCanariesCommand = new RelayCommand(VerifyCanariesAsync);
        ScanUsbNowCommand = new RelayCommand(ScanUsbNowAsync);
        SaveScheduleCommand = new RelayCommand(SaveScheduleAsync);
        RunScheduledUpdateNowCommand = new RelayCommand(RunScheduledUpdateNowAsync);
        RegisterContextMenuCommand = new RelayCommand(() => { RegisterContextMenu(); return Task.CompletedTask; });
        UnregisterContextMenuCommand = new RelayCommand(() => { UnregisterContextMenu(); return Task.CompletedTask; });
    }

    public ObservableCollection<string> MonitoredFolders { get; } = new();
    public ObservableCollection<RealTimeGuardEvent> GuardEvents { get; } = new();
    public ObservableCollection<QuarantineEntry> QuarantineEntries { get; } = new();
    public ObservableCollection<YaraProcessMatch> ProcessMatches { get; } = new();
    public ObservableCollection<PeSectionInfo> ForensicsSections { get; } = new();
    public ObservableCollection<string> ForensicsRiskReasons { get; } = new();
    public ObservableCollection<CanaryFileStatus> Canaries { get; } = new();
    public ObservableCollection<CanaryAlertEvent> CanaryAlerts { get; } = new();
    public ObservableCollection<ClipboardHijackAlert> ClipboardAlerts { get; } = new();
    public ObservableCollection<UsbAutoScanEvent> UsbScanEvents { get; } = new();

    public RelayCommand LoadCommand { get; }
    public RelayCommand RefreshQuarantineCommand { get; }
    public RelayCommand ScanAllProcessesCommand { get; }
    public RelayCommand ScanSinglePidCommand { get; }
    public RelayCommand CancelProcessScanCommand { get; }
    public RelayCommand AnalyzeForensicsCommand { get; }
    public RelayCommand InvestigateForensicsWithAiCommand { get; }
    public RelayCommand VerifyCanariesCommand { get; }
    public RelayCommand ScanUsbNowCommand { get; }
    public RelayCommand SaveScheduleCommand { get; }
    public RelayCommand RunScheduledUpdateNowCommand { get; }
    public RelayCommand RegisterContextMenuCommand { get; }
    public RelayCommand UnregisterContextMenuCommand { get; }

    public bool FolderGuardEnabled
    {
        get => _folderGuardEnabled;
        set
        {
            if (SetProperty(ref _folderGuardEnabled, value) && !_isLoading)
                _ = ToggleFolderGuardAsync(value);
        }
    }

    public bool AutoQuarantineEnabled
    {
        get => _autoQuarantineEnabled;
        set
        {
            if (SetProperty(ref _autoQuarantineEnabled, value))
            {
                _folderGuard.AutoQuarantineEnabled = value;
                if (!_isLoading)
                {
                    _settings.Current.RealTimeYaraAutoQuarantine = value;
                    _ = _settings.SaveAsync();
                }
            }
        }
    }

    public string FolderGuardStatus { get => _folderGuardStatus; set => SetProperty(ref _folderGuardStatus, value); }

    public string TargetPidText
    {
        get => _targetPidText;
        set
        {
            if (SetProperty(ref _targetPidText, value))
                ScanSinglePidCommand.RaiseCanExecuteChanged();
        }
    }

    public bool IsScanningProcesses
    {
        get => _isScanningProcesses;
        set
        {
            if (SetProperty(ref _isScanningProcesses, value))
            {
                ScanAllProcessesCommand.RaiseCanExecuteChanged();
                ScanSinglePidCommand.RaiseCanExecuteChanged();
                CancelProcessScanCommand.RaiseCanExecuteChanged();
            }
        }
    }

    public double ProcScanPercent { get => _procScanPercent; set => SetProperty(ref _procScanPercent, value); }
    public string ProcScanStatus { get => _procScanStatus; set => SetProperty(ref _procScanStatus, value); }

    public string ForensicsFilePath
    {
        get => _forensicsFilePath;
        set
        {
            if (SetProperty(ref _forensicsFilePath, value))
                AnalyzeForensicsCommand.RaiseCanExecuteChanged();
        }
    }

    public FileForensicsReport? CurrentForensics
    {
        get => _currentForensics;
        set
        {
            if (SetProperty(ref _currentForensics, value))
            {
                OnPropertyChanged(nameof(HasForensics));
                InvestigateForensicsWithAiCommand.RaiseCanExecuteChanged();
            }
        }
    }

    public bool HasForensics => CurrentForensics is not null;
    public string ForensicsSummary { get => _forensicsSummary; set => SetProperty(ref _forensicsSummary, value); }

    public bool CanaryEnabled
    {
        get => _canaryEnabled;
        set
        {
            if (SetProperty(ref _canaryEnabled, value) && !_isLoading)
                _ = ToggleCanaryAsync(value);
        }
    }

    public string CanaryStatus { get => _canaryStatus; set => SetProperty(ref _canaryStatus, value); }

    public bool ClipboardGuardEnabled
    {
        get => _clipboardGuardEnabled;
        set
        {
            if (SetProperty(ref _clipboardGuardEnabled, value) && !_isLoading)
                _ = ToggleClipboardGuardAsync(value);
        }
    }

    public string ClipboardStatus { get => _clipboardStatus; set => SetProperty(ref _clipboardStatus, value); }

    public bool UsbAutoScanEnabled
    {
        get => _usbAutoScanEnabled;
        set
        {
            if (SetProperty(ref _usbAutoScanEnabled, value) && !_isLoading)
                _ = ToggleUsbAutoScanAsync(value);
        }
    }

    public string UsbStatus { get => _usbStatus; set => SetProperty(ref _usbStatus, value); }

    public bool ScheduledYaraEnabled { get => _scheduledYaraEnabled; set => SetProperty(ref _scheduledYaraEnabled, value); }
    public double ScheduledIntervalHours { get => _scheduledIntervalHours; set => SetProperty(ref _scheduledIntervalHours, value); }
    public string ScheduledYaraStatus { get => _scheduledYaraStatus; set => SetProperty(ref _scheduledYaraStatus, value); }

    public bool ContextMenuRegistered { get => _contextMenuRegistered; set => SetProperty(ref _contextMenuRegistered, value); }
    public string ContextMenuStatus { get => _contextMenuStatus; set => SetProperty(ref _contextMenuStatus, value); }

    public async Task LoadAsync()
    {
        _isLoading = true;
        ClearMessages();
        try
        {
            FolderGuardEnabled = _folderGuard.IsRunning;
            AutoQuarantineEnabled = _settings.Current.RealTimeYaraAutoQuarantine;
            _folderGuard.AutoQuarantineEnabled = AutoQuarantineEnabled;
            RefreshFolderGuardView();

            CanaryEnabled = _canary.IsArmed;
            RefreshCanaryView();

            ClipboardGuardEnabled = _clipboardGuard.IsEnabled;
            ClipboardStatus = ClipboardGuardEnabled
                ? "Active — watching clipboard for wallet/IBAN clipper hijacks."
                : "Inactive";
            ClipboardAlerts.Clear();
            foreach (var a in _clipboardGuard.RecentAlerts)
                ClipboardAlerts.Add(a);

            UsbAutoScanEnabled = _usbAutoScan.IsEnabled;
            RefreshUsbView();

            await _scheduledYara.LoadConfigAsync();
            ScheduledYaraEnabled = _scheduledYara.CurrentConfig.Enabled;
            ScheduledIntervalHours = _scheduledYara.CurrentConfig.IntervalHours;
            ScheduledYaraStatus = _scheduledYara.CurrentConfig.LastStatus;

            RefreshContextMenuStatus();
            await RefreshQuarantineAsync();
        }
        finally
        {
            _isLoading = false;
        }
    }

    private async Task ToggleFolderGuardAsync(bool enable)
    {
        ClearMessages();
        if (enable)
        {
            var res = await _folderGuard.StartAsync();
            if (!res.Success)
            {
                ErrorMessage = res.Message;
                _isLoading = true;
                FolderGuardEnabled = false;
                _isLoading = false;
            }
            else
            {
                StatusMessage = res.Message;
            }
        }
        else
        {
            _folderGuard.Stop();
            StatusMessage = "Real-Time YARA Folder Guard stopped.";
        }

        _settings.Current.RealTimeYaraGuardEnabled = _folderGuard.IsRunning;
        await _settings.SaveAsync();
        RefreshFolderGuardView();
    }

    public void RefreshFolderGuardView()
    {
        MonitoredFolders.Clear();
        foreach (var f in _folderGuard.MonitoredFolders)
            MonitoredFolders.Add(f);

        GuardEvents.Clear();
        foreach (var ev in _folderGuard.RecentEvents.Take(25))
            GuardEvents.Add(ev);

        FolderGuardStatus = _folderGuard.IsRunning
            ? $"Active — watching {MonitoredFolders.Count} folder(s) with Native YARA Engine."
            : "Stopped";
    }

    public async Task RefreshQuarantineAsync()
    {
        var res = await _quarantine.GetEntriesAsync();
        QuarantineEntries.Clear();
        if (res.Success && res.Value is not null)
        {
            foreach (var e in res.Value)
                QuarantineEntries.Add(e);
        }
    }

    public async Task RestoreQuarantineEntryAsync(string entryId)
    {
        ClearMessages();
        var res = await _quarantine.RestoreFileAsync(entryId);
        if (res.Success)
            StatusMessage = res.Message;
        else
            ErrorMessage = res.Message;
        await RefreshQuarantineAsync();
    }

    public async Task DeleteQuarantineEntryAsync(string entryId)
    {
        ClearMessages();
        var res = await _quarantine.DeletePermanentlyAsync(entryId);
        if (res.Success)
            StatusMessage = res.Message;
        else
            ErrorMessage = res.Message;
        await RefreshQuarantineAsync();
    }

    public async Task ScanAllProcessesAsync()
    {
        if (IsScanningProcesses)
            return;

        IsScanningProcesses = true;
        ClearMessages();
        ProcessMatches.Clear();
        ProcScanPercent = 0;
        ProcScanStatus = "Enumerating running processes and scanning memory with yara64.exe...";

        _procScanCts?.Dispose();
        _procScanCts = new CancellationTokenSource();

        try
        {
            var progress = new Progress<YaraScanProgress>(p =>
            {
                ProcScanPercent = p.PercentComplete;
                ProcScanStatus = $"Scanning {p.CurrentFile} ({p.FilesScanned}/{p.TotalFiles}) — {p.MatchesFound} match(es)";
            });

            var res = await _yara.ScanRunningProcessesAsync(progress, _procScanCts.Token);
            if (!res.Success || res.Value is null)
            {
                ErrorMessage = res.Message;
                ProcScanStatus = res.Message;
                return;
            }

            foreach (var m in res.Value.Matches)
                ProcessMatches.Add(m);

            ProcScanPercent = 100;
            ProcScanStatus = res.Message;
            StatusMessage = res.Message;
        }
        finally
        {
            IsScanningProcesses = false;
        }
    }

    public async Task ScanSinglePidAsync()
    {
        if (IsScanningProcesses || !int.TryParse(TargetPidText.Trim(), out var pid))
            return;

        IsScanningProcesses = true;
        ClearMessages();
        ProcessMatches.Clear();
        ProcScanStatus = $"Scanning PID {pid} in memory via yara64.exe...";
        try
        {
            var res = await _yara.ScanProcessAsync(pid);
            if (!res.Success || res.Value is null)
            {
                ErrorMessage = res.Message;
                ProcScanStatus = res.Message;
                return;
            }

            foreach (var m in res.Value.Matches)
                ProcessMatches.Add(m);

            ProcScanStatus = res.Message;
            StatusMessage = res.Message;
        }
        finally
        {
            IsScanningProcesses = false;
        }
    }

    private void CancelProcessScan()
    {
        try { _procScanCts?.Cancel(); } catch { }
    }

    public async Task AnalyzeForensicsAsync()
    {
        if (string.IsNullOrWhiteSpace(ForensicsFilePath))
            return;

        IsBusy = true;
        ClearMessages();
        try
        {
            var res = await _forensics.AnalyzeFileAsync(ForensicsFilePath.Trim());
            if (!res.Success || res.Value is null)
            {
                ErrorMessage = res.Message;
                return;
            }

            var r = res.Value;
            CurrentForensics = r;

            ForensicsSections.Clear();
            foreach (var s in r.Sections)
                ForensicsSections.Add(s);

            ForensicsRiskReasons.Clear();
            foreach (var reason in r.RiskReasons)
                ForensicsRiskReasons.Add(reason);

            var apis = r.SuspiciousApis.Count > 0 ? string.Join(", ", r.SuspiciousApis) : "None";
            ForensicsSummary =
                $"File: {r.FileName} ({r.FileSizeBytes:N0} bytes) · Risk: {r.RiskAssessment}\n" +
                $"SHA-256: {r.Sha256}\n" +
                $"Shannon Entropy: {r.FileEntropy:F2} / 8.00 ({(r.IsLikelyPackedOrEncrypted ? "High — likely packed/encrypted" : "Normal")})\n" +
                $"PE Format: {r.PeArchitecture} · Authenticode: {r.Signature.Status}" +
                (string.IsNullOrWhiteSpace(r.Signature.Subject) ? string.Empty : $" ({r.Signature.Subject})") + "\n" +
                $"Sensitive Windows APIs: {apis}";

            StatusMessage = res.Message;
        }
        finally
        {
            IsBusy = false;
        }
    }

    private void InvestigateForensicsWithAi()
    {
        if (CurrentForensics is null)
            return;
        var prompt = AiYaraRuleHelper.BuildThreatInvestigatorPrompt(null, CurrentForensics, _localization.ShortCode);
        App.MainWindow?.NavigateTo("Ai", prompt);
    }

    private async Task ToggleCanaryAsync(bool enable)
    {
        ClearMessages();
        if (enable)
        {
            var res = await _canary.ArmAsync();
            if (!res.Success)
            {
                ErrorMessage = res.Message;
                _isLoading = true;
                CanaryEnabled = false;
                _isLoading = false;
            }
            else
            {
                StatusMessage = res.Message;
            }
        }
        else
        {
            _canary.Disarm(removeDecoyFiles: true);
            StatusMessage = "Ransomware Canary Guard disarmed and decoy files removed.";
        }

        _settings.Current.RansomwareCanaryEnabled = _canary.IsArmed;
        await _settings.SaveAsync();
        RefreshCanaryView();
    }

    public async Task VerifyCanariesAsync()
    {
        ClearMessages();
        var res = await _canary.VerifyIntegrityAsync();
        RefreshCanaryView();
        StatusMessage = res.Message;
    }

    public void RefreshCanaryView()
    {
        Canaries.Clear();
        foreach (var c in _canary.ActiveCanaries)
            Canaries.Add(c);

        CanaryAlerts.Clear();
        foreach (var a in _canary.RecentAlerts)
            CanaryAlerts.Add(a);

        CanaryStatus = _canary.IsArmed
            ? $"Armed — protecting {Canaries.Count} folder(s) with hidden SHA-256 sentinel decoys."
            : "Disarmed";
    }

    private async Task ToggleClipboardGuardAsync(bool enable)
    {
        _clipboardGuard.IsEnabled = enable;
        _settings.Current.ClipboardGuardEnabled = enable;
        await _settings.SaveAsync();
        ClipboardStatus = enable
            ? "Active — watching clipboard for wallet/IBAN clipper hijacks."
            : "Inactive";
        StatusMessage = enable ? "Clipboard Hijack Guard enabled." : "Clipboard Hijack Guard disabled.";
    }

    private async Task ToggleUsbAutoScanAsync(bool enable)
    {
        if (enable)
            _usbAutoScan.Start();
        else
            _usbAutoScan.Stop();

        _settings.Current.UsbAutoScanEnabled = _usbAutoScan.IsEnabled;
        await _settings.SaveAsync();
        RefreshUsbView();
        StatusMessage = enable ? "USB Auto-Scan on insertion enabled." : "USB Auto-Scan disabled.";
    }

    public async Task ScanUsbNowAsync()
    {
        ClearMessages();
        var drives = DriveInfo.GetDrives()
            .Where(d => d.DriveType == DriveType.Removable && d.IsReady)
            .Select(d => d.RootDirectory.FullName)
            .ToList();

        if (drives.Count == 0)
        {
            StatusMessage = "No ready USB removable drives are currently connected.";
            return;
        }

        IsBusy = true;
        try
        {
            foreach (var root in drives)
            {
                var res = await _usbAutoScan.ScanDriveNowAsync(root);
                if (!res.Success)
                    ErrorMessage = res.Message;
                else
                    StatusMessage = res.Message;
            }
            RefreshUsbView();
        }
        finally
        {
            IsBusy = false;
        }
    }

    public void RefreshUsbView()
    {
        UsbScanEvents.Clear();
        foreach (var ev in _usbAutoScan.RecentScans)
            UsbScanEvents.Add(ev);

        var drives = _usbAutoScan.KnownRemovableDrives;
        UsbStatus = _usbAutoScan.IsEnabled
            ? $"Active — auto-scans newly inserted USB drives with Native YARA ({drives.Count} removable drive(s) currently mounted)."
            : "Inactive";
    }

    public async Task SaveScheduleAsync()
    {
        ClearMessages();
        var cfg = _scheduledYara.CurrentConfig;
        cfg.Enabled = ScheduledYaraEnabled;
        cfg.IntervalHours = double.IsNaN(ScheduledIntervalHours) ? 24 : Math.Clamp((int)Math.Round(ScheduledIntervalHours), 1, 720);
        var res = await _scheduledYara.SaveConfigAsync(cfg);
        if (res.Success)
            StatusMessage = res.Message;
        else
            ErrorMessage = res.Message;
        ScheduledYaraStatus = _scheduledYara.CurrentConfig.LastStatus;
    }

    public async Task RunScheduledUpdateNowAsync()
    {
        IsBusy = true;
        ClearMessages();
        try
        {
            var res = await _scheduledYara.RunScheduledUpdateNowAsync();
            ScheduledYaraStatus = _scheduledYara.CurrentConfig.LastStatus;
            if (res.Success)
                StatusMessage = res.Message;
            else
                ErrorMessage = res.Message;
        }
        finally
        {
            IsBusy = false;
        }
    }

    private void RegisterContextMenu()
    {
        ClearMessages();
        var res = _contextMenu.Register();
        if (res.Success) StatusMessage = res.Message;
        else ErrorMessage = res.Message;
        RefreshContextMenuStatus();
    }

    private void UnregisterContextMenu()
    {
        ClearMessages();
        var res = _contextMenu.Unregister();
        if (res.Success) StatusMessage = res.Message;
        else ErrorMessage = res.Message;
        RefreshContextMenuStatus();
    }

    private void RefreshContextMenuStatus()
    {
        ContextMenuRegistered = _contextMenu.IsRegistered();
        ContextMenuStatus = ContextMenuRegistered
            ? "Registered — right-click any file or folder in Windows Explorer and choose 'Scan with BECETTI YARA'."
            : "Not registered";
    }
}
