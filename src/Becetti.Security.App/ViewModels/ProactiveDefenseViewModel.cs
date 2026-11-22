using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Windows.Input;
using Becetti.Security.App.Services;
using Becetti.Security.Core.Models;
using Becetti.Security.Core.Services;

namespace Becetti.Security.App.ViewModels;

public sealed class ProactiveDefenseViewModel : ViewModelBase
{
    private readonly IBrowserExtensionAuditorService _browserAuditor;
    private readonly ISoftwareUpdateAuditorService _softwareAuditor;
    private readonly IWifiArpGuardService _wifiArp;
    private readonly IProcessDllInspectorService _dllInspector;
    private readonly ISecureShredderService _shredder;
    private readonly IPasswordBreachService _passwordChecker;
    private readonly IScanSchedulerService _scheduler;
    private readonly IExecutiveHtmlReportService _reports;
    private readonly IYaraEngineService _yara;
    private readonly ISettingsService _settings;
    private readonly IEventLogService _events;
    private readonly IAiTriageNavigator _aiTriage;

    private string _browserSummary = "Click 'Audit Browser Extensions' to inspect Chrome, Edge, Brave, and Firefox.";
    private BrowserExtensionItem? _selectedExtension;

    private string _softwareSummary = "Click 'Check Outdated Apps' to query Windows Package Manager (winget).";
    private OutdatedSoftwareItem? _selectedSoftware;

    private string _wifiSummary = "Click 'Audit Wi-Fi & ARP' to inspect encryption and check for ARP Spoofing / MITM.";
    private string _wifiDetails = "";
    private bool _arpAlertActive;

    private string _dllSummary = "Click 'Inspect Process DLLs' to detect unsigned or suspicious-path injected modules.";
    private string _targetPidInput = string.Empty;
    private ProcessDllInfo? _selectedDll;

    private string _shredFilePath = string.Empty;
    private bool _shredSevenPass;
    private string _shredResult = string.Empty;

    private string _passwordToCheck = string.Empty;
    private string _passwordSummary = "Uses HaveIBeenPwned k-Anonymity (only first 5 SHA-1 characters leave your PC).";

    private bool _scheduledScanEnabled;
    private int _scheduledIntervalIndex; // 0 = Daily (24h), 1 = Weekly (168h)
    private string _automationSummary = string.Empty;
    private string _lastReportPath = string.Empty;

    public ProactiveDefenseViewModel(
        IBrowserExtensionAuditorService browserAuditor,
        ISoftwareUpdateAuditorService softwareAuditor,
        IWifiArpGuardService wifiArp,
        IProcessDllInspectorService dllInspector,
        ISecureShredderService shredder,
        IPasswordBreachService passwordChecker,
        IScanSchedulerService scheduler,
        IExecutiveHtmlReportService reports,
        IYaraEngineService yara,
        ISettingsService settings,
        IEventLogService events,
        IAiTriageNavigator aiTriage)
    {
        _browserAuditor = browserAuditor;
        _softwareAuditor = softwareAuditor;
        _wifiArp = wifiArp;
        _dllInspector = dllInspector;
        _shredder = shredder;
        _passwordChecker = passwordChecker;
        _scheduler = scheduler;
        _reports = reports;
        _yara = yara;
        _settings = settings;
        _events = events;
        _aiTriage = aiTriage;

        _scheduledScanEnabled = _settings.Current.ScheduledScanEnabled;
        _scheduledIntervalIndex = _settings.Current.ScheduledScanIntervalHours >= 168 ? 1 : 0;

        AuditBrowsersCommand = new RelayCommand(AuditBrowsersAsync, () => !IsBusy);
        AskAiExtensionCommand = new RelayCommand(AskAiAboutExtensionAsync, () => SelectedExtension is not null);

        CheckSoftwareCommand = new RelayCommand(CheckSoftwareAsync, () => !IsBusy);
        UpgradeSelectedSoftwareCommand = new RelayCommand(UpgradeSelectedSoftwareAsync, () => !IsBusy && SelectedSoftware is not null);

        AuditWifiArpCommand = new RelayCommand(AuditWifiArpAsync, () => !IsBusy);
        AskAiWifiArpCommand = new RelayCommand(AskAiAboutWifiArpAsync);

        AuditDllsCommand = new RelayCommand(AuditDllsAsync, () => !IsBusy);
        ScanSelectedDllYaraCommand = new RelayCommand(ScanSelectedDllYaraAsync, () => !IsBusy && SelectedDll is not null);
        AskAiDllCommand = new RelayCommand(AskAiAboutDllAsync, () => SelectedDll is not null);

        ShredFileCommand = new RelayCommand(ShredFileAsync, () => !IsBusy && !string.IsNullOrWhiteSpace(ShredFilePath));
        CheckPasswordCommand = new RelayCommand(CheckPasswordAsync, () => !IsBusy && !string.IsNullOrEmpty(PasswordToCheck));

        GenerateReportCommand = new RelayCommand(GenerateExecutiveReportAsync, () => !IsBusy);
        RunScheduledAuditNowCommand = new RelayCommand(RunScheduledAuditNowAsync, () => !IsBusy);
        ExportPolicyCommand = new RelayCommand(ExportPolicyAsync, () => !IsBusy);
    }

    public ObservableCollection<BrowserExtensionItem> Extensions { get; } = new();
    public ObservableCollection<OutdatedSoftwareItem> OutdatedPackages { get; } = new();
    public ObservableCollection<string> WifiArpAlerts { get; } = new();
    public ObservableCollection<ArpEntryInfo> ArpEntries { get; } = new();
    public ObservableCollection<ProcessDllInfo> LoadedDlls { get; } = new();

    public string BrowserSummary { get => _browserSummary; set => SetProperty(ref _browserSummary, value); }
    public BrowserExtensionItem? SelectedExtension
    {
        get => _selectedExtension;
        set { if (SetProperty(ref _selectedExtension, value)) NotifyCommandStates(); }
    }

    public string SoftwareSummary { get => _softwareSummary; set => SetProperty(ref _softwareSummary, value); }
    public OutdatedSoftwareItem? SelectedSoftware
    {
        get => _selectedSoftware;
        set { if (SetProperty(ref _selectedSoftware, value)) NotifyCommandStates(); }
    }

    public string WifiSummary { get => _wifiSummary; set => SetProperty(ref _wifiSummary, value); }
    public string WifiDetails { get => _wifiDetails; set => SetProperty(ref _wifiDetails, value); }
    public bool ArpAlertActive { get => _arpAlertActive; set => SetProperty(ref _arpAlertActive, value); }

    public string DllSummary { get => _dllSummary; set => SetProperty(ref _dllSummary, value); }
    public string TargetPidInput { get => _targetPidInput; set => SetProperty(ref _targetPidInput, value); }
    public ProcessDllInfo? SelectedDll
    {
        get => _selectedDll;
        set { if (SetProperty(ref _selectedDll, value)) NotifyCommandStates(); }
    }

    public string ShredFilePath
    {
        get => _shredFilePath;
        set { if (SetProperty(ref _shredFilePath, value)) NotifyCommandStates(); }
    }
    public bool ShredSevenPass { get => _shredSevenPass; set => SetProperty(ref _shredSevenPass, value); }
    public string ShredResult { get => _shredResult; set => SetProperty(ref _shredResult, value); }

    public string PasswordToCheck
    {
        get => _passwordToCheck;
        set { if (SetProperty(ref _passwordToCheck, value)) NotifyCommandStates(); }
    }
    public string PasswordSummary { get => _passwordSummary; set => SetProperty(ref _passwordSummary, value); }

    public bool ScheduledScanEnabled
    {
        get => _scheduledScanEnabled;
        set
        {
            if (SetProperty(ref _scheduledScanEnabled, value))
                _ = SaveSchedulerSettingsAsync();
        }
    }

    public int ScheduledIntervalIndex
    {
        get => _scheduledIntervalIndex;
        set
        {
            if (SetProperty(ref _scheduledIntervalIndex, value))
                _ = SaveSchedulerSettingsAsync();
        }
    }

    public string AutomationSummary { get => _automationSummary; set => SetProperty(ref _automationSummary, value); }
    public string LastReportPath { get => _lastReportPath; set => SetProperty(ref _lastReportPath, value); }

    public ICommand AuditBrowsersCommand { get; }
    public ICommand AskAiExtensionCommand { get; }
    public ICommand CheckSoftwareCommand { get; }
    public ICommand UpgradeSelectedSoftwareCommand { get; }
    public ICommand AuditWifiArpCommand { get; }
    public ICommand AskAiWifiArpCommand { get; }
    public ICommand AuditDllsCommand { get; }
    public ICommand ScanSelectedDllYaraCommand { get; }
    public ICommand AskAiDllCommand { get; }
    public ICommand ShredFileCommand { get; }
    public ICommand CheckPasswordCommand { get; }
    public ICommand GenerateReportCommand { get; }
    public ICommand RunScheduledAuditNowCommand { get; }
    public ICommand ExportPolicyCommand { get; }

    private void NotifyCommandStates()
    {
        (AuditBrowsersCommand as RelayCommand)?.RaiseCanExecuteChanged();
        (AskAiExtensionCommand as RelayCommand)?.RaiseCanExecuteChanged();
        (CheckSoftwareCommand as RelayCommand)?.RaiseCanExecuteChanged();
        (UpgradeSelectedSoftwareCommand as RelayCommand)?.RaiseCanExecuteChanged();
        (AuditWifiArpCommand as RelayCommand)?.RaiseCanExecuteChanged();
        (AuditDllsCommand as RelayCommand)?.RaiseCanExecuteChanged();
        (ScanSelectedDllYaraCommand as RelayCommand)?.RaiseCanExecuteChanged();
        (AskAiDllCommand as RelayCommand)?.RaiseCanExecuteChanged();
        (ShredFileCommand as RelayCommand)?.RaiseCanExecuteChanged();
        (CheckPasswordCommand as RelayCommand)?.RaiseCanExecuteChanged();
        (GenerateReportCommand as RelayCommand)?.RaiseCanExecuteChanged();
        (RunScheduledAuditNowCommand as RelayCommand)?.RaiseCanExecuteChanged();
        (ExportPolicyCommand as RelayCommand)?.RaiseCanExecuteChanged();
    }

    public async Task AuditBrowsersAsync()
    {
        ClearMessages();
        IsBusy = true;
        NotifyCommandStates();
        try
        {
            var res = await _browserAuditor.AuditAsync();
            if (!res.Success || res.Value is null) { ErrorMessage = res.Message; return; }
            Extensions.Clear();
            foreach (var e in res.Value.Extensions) Extensions.Add(e);
            BrowserSummary = res.Message;
            StatusMessage = res.Message;
            await _events.RecordAsync("BrowserAudit", res.Message, res.Value.HighRiskCount == 0);
        }
        finally { IsBusy = false; NotifyCommandStates(); }
    }

    private Task AskAiAboutExtensionAsync()
    {
        if (SelectedExtension is null) return Task.CompletedTask;
        var ext = SelectedExtension;
        var prompt = $"Analyze this browser extension detected by BECETTI SECURITY:\n" +
                     $"Browser: {ext.Browser} ({ext.Profile})\nName: {ext.Name} v{ext.Version}\nID: {ext.ExtensionId}\n" +
                     $"Risk: {ext.RiskLevel}\nRisky Permissions: {string.Join(", ", ext.RiskyPermissions)}\n" +
                     $"Should I keep or remove this extension? Explain the privacy/security risks concisely.";
        _aiTriage.SendToBecettiAi(prompt);
        return Task.CompletedTask;
    }

    public async Task CheckSoftwareAsync()
    {
        ClearMessages();
        IsBusy = true;
        NotifyCommandStates();
        try
        {
            var res = await _softwareAuditor.CheckOutdatedAsync();
            if (!res.Success || res.Value is null) { ErrorMessage = res.Message; return; }
            OutdatedPackages.Clear();
            foreach (var p in res.Value.Packages) OutdatedPackages.Add(p);
            SoftwareSummary = res.Value.Notes;
            StatusMessage = res.Message;
        }
        finally { IsBusy = false; NotifyCommandStates(); }
    }

    private async Task UpgradeSelectedSoftwareAsync()
    {
        if (SelectedSoftware is null) return;
        ClearMessages();
        IsBusy = true;
        NotifyCommandStates();
        try
        {
            var id = SelectedSoftware.PackageId;
            var res = await _softwareAuditor.UpgradePackageAsync(id);
            if (!res.Success) { ErrorMessage = res.Message; return; }
            StatusMessage = res.Message;
            await _events.RecordAsync("SoftwareUpgrade", res.Message, true);
            await CheckSoftwareAsync();
        }
        finally { IsBusy = false; NotifyCommandStates(); }
    }

    public async Task AuditWifiArpAsync()
    {
        ClearMessages();
        IsBusy = true;
        NotifyCommandStates();
        try
        {
            var res = await _wifiArp.AuditAsync();
            if (!res.Success || res.Value is null) { ErrorMessage = res.Message; return; }
            var r = res.Value;
            WifiSummary = res.Message;
            WifiDetails = r.Wifi.IsConnected
                ? $"SSID: {r.Wifi.Ssid} · Auth: {r.Wifi.Authentication} · Cipher: {r.Wifi.Cipher} · Signal: {r.Wifi.SignalStrength} · Gateway: {r.DefaultGatewayIp} ({r.DefaultGatewayMac})"
                : $"{r.Wifi.RiskReason} · Gateway: {r.DefaultGatewayIp} ({r.DefaultGatewayMac})";
            ArpAlertActive = r.ArpSpoofingSuspected || r.Alerts.Count > 0;
            WifiArpAlerts.Clear();
            foreach (var a in r.Alerts) WifiArpAlerts.Add(a);
            ArpEntries.Clear();
            foreach (var e in r.ArpEntries) ArpEntries.Add(e);
            StatusMessage = res.Message;
            await _events.RecordAsync("WifiArpAudit", res.Message, !ArpAlertActive);
        }
        finally { IsBusy = false; NotifyCommandStates(); }
    }

    private Task AskAiAboutWifiArpAsync()
    {
        var alerts = WifiArpAlerts.Count > 0 ? string.Join(" | ", WifiArpAlerts) : "No alerts";
        var prompt = $"Analyze my Wi-Fi & ARP Security Audit from BECETTI SECURITY:\n{WifiDetails}\nAlerts: {alerts}\n" +
                     $"Give me clear steps to verify whether my network is safe from MITM or ARP spoofing.";
        _aiTriage.SendToBecettiAi(prompt);
        return Task.CompletedTask;
    }

    public async Task AuditDllsAsync()
    {
        ClearMessages();
        IsBusy = true;
        NotifyCommandStates();
        try
        {
            int? pid = int.TryParse(TargetPidInput?.Trim(), out var parsedPid) && parsedPid > 0 ? parsedPid : null;
            var res = await _dllInspector.AuditLoadedModulesAsync(pid);
            if (!res.Success || res.Value is null) { ErrorMessage = res.Message; return; }
            LoadedDlls.Clear();
            foreach (var m in res.Value.Modules) LoadedDlls.Add(m);
            DllSummary = res.Message;
            StatusMessage = res.Message;
        }
        finally { IsBusy = false; NotifyCommandStates(); }
    }

    private async Task ScanSelectedDllYaraAsync()
    {
        if (SelectedDll is null || string.IsNullOrWhiteSpace(SelectedDll.FilePath)) return;
        ClearMessages();
        IsBusy = true;
        NotifyCommandStates();
        try
        {
            var res = await _yara.ScanAsync(SelectedDll.FilePath, recursive: false);
            if (!res.Success || res.Value is null) { ErrorMessage = res.Message; return; }
            StatusMessage = res.Value.Matches.Count == 0
                ? $"YARA Scan Clean: 0 rule matches in {SelectedDll.ModuleName}."
                : $"YARA ALERT: {res.Value.Matches.Count} match(es) in {SelectedDll.ModuleName} ({string.Join(", ", res.Value.Matches.Select(m => m.RuleName).Distinct())})!";
            await _events.RecordAsync("DllYaraScan", StatusMessage, res.Value.Matches.Count == 0);
        }
        finally { IsBusy = false; NotifyCommandStates(); }
    }

    private Task AskAiAboutDllAsync()
    {
        if (SelectedDll is null) return Task.CompletedTask;
        var d = SelectedDll;
        var prompt = $"Analyze this loaded Windows DLL module flagged by BECETTI SECURITY:\n" +
                     $"Process: {d.ProcessName} (PID {d.ProcessId})\nModule: {d.ModuleName}\nPath: {d.FilePath}\n" +
                     $"Signature: {d.SignatureStatus} ({d.Publisher})\nRisk: {d.RiskLevel} — {d.RiskReason}\n" +
                     $"Could this be DLL sideloading or injection, and what should I check next?";
        _aiTriage.SendToBecettiAi(prompt);
        return Task.CompletedTask;
    }

    private async Task ShredFileAsync()
    {
        ClearMessages();
        IsBusy = true;
        NotifyCommandStates();
        try
        {
            int passes = ShredSevenPass ? 7 : 3;
            var res = await _shredder.ShredFileAsync(ShredFilePath, passes);
            if (!res.Success || res.Value is null) { ErrorMessage = res.Message; return; }
            ShredResult = res.Message;
            StatusMessage = res.Message;
            ShredFilePath = string.Empty;
            await _events.RecordAsync("SecureShred", res.Message, true);
        }
        finally { IsBusy = false; NotifyCommandStates(); }
    }

    private async Task CheckPasswordAsync()
    {
        ClearMessages();
        IsBusy = true;
        NotifyCommandStates();
        try
        {
            var res = await _passwordChecker.CheckPasswordAsync(PasswordToCheck, queryHibp: true);
            if (!res.Success || res.Value is null) { ErrorMessage = res.Message; return; }
            PasswordSummary = res.Value.Advice;
            StatusMessage = $"Strength: {res.Value.StrengthRating} ({res.Value.EntropyBits:F1} bits) · Prefix: {res.Value.Sha1PrefixSent}";
        }
        finally
        {
            PasswordToCheck = string.Empty;
            IsBusy = false;
            NotifyCommandStates();
        }
    }

    public async Task GenerateExecutiveReportAsync()
    {
        ClearMessages();
        IsBusy = true;
        NotifyCommandStates();
        try
        {
            var res = await _reports.GenerateExecutiveHtmlReportAsync();
            if (!res.Success || res.Value is null) { ErrorMessage = res.Message; return; }
            LastReportPath = res.Value.ReportPath;
            AutomationSummary = res.Message;
            StatusMessage = res.Message;
            try
            {
                Process.Start(new ProcessStartInfo { FileName = res.Value.ReportPath, UseShellExecute = true });
            }
            catch { }
        }
        finally { IsBusy = false; NotifyCommandStates(); }
    }

    private async Task RunScheduledAuditNowAsync()
    {
        ClearMessages();
        IsBusy = true;
        NotifyCommandStates();
        try
        {
            var res = await _scheduler.RunScheduledAuditNowAsync();
            if (!res.Success) { ErrorMessage = res.Message; return; }
            AutomationSummary = res.Message;
            StatusMessage = res.Message;
        }
        finally { IsBusy = false; NotifyCommandStates(); }
    }

    private async Task ExportPolicyAsync()
    {
        ClearMessages();
        IsBusy = true;
        NotifyCommandStates();
        try
        {
            var res = await _scheduler.ExportPolicyAsync();
            if (!res.Success) { ErrorMessage = res.Message; return; }
            AutomationSummary = res.Message;
            StatusMessage = res.Message;
        }
        finally { IsBusy = false; NotifyCommandStates(); }
    }

    public async Task ImportPolicyFromFileAsync(string filePath)
    {
        ClearMessages();
        IsBusy = true;
        NotifyCommandStates();
        try
        {
            var res = await _scheduler.ImportPolicyAsync(filePath);
            if (!res.Success) { ErrorMessage = res.Message; return; }
            _scheduledScanEnabled = _settings.Current.ScheduledScanEnabled;
            _scheduledIntervalIndex = _settings.Current.ScheduledScanIntervalHours >= 168 ? 1 : 0;
            OnPropertyChanged(nameof(ScheduledScanEnabled));
            OnPropertyChanged(nameof(ScheduledIntervalIndex));
            AutomationSummary = res.Message;
            StatusMessage = res.Message;
        }
        finally { IsBusy = false; NotifyCommandStates(); }
    }

    private async Task SaveSchedulerSettingsAsync()
    {
        _settings.Current.ScheduledScanEnabled = _scheduledScanEnabled;
        _settings.Current.ScheduledScanIntervalHours = _scheduledIntervalIndex == 1 ? 168 : 24;
        await _settings.SaveAsync();
        if (_scheduledScanEnabled) _scheduler.Start();
        else _scheduler.Stop();
        AutomationSummary = _scheduledScanEnabled
            ? $"Automated Audit enabled (every {_settings.Current.ScheduledScanIntervalHours}h)."
            : "Automated Audit Scheduler paused.";
    }
}
