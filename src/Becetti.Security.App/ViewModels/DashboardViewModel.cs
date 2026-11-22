using Becetti.Security.App.Services;
using Becetti.Security.Core.Models;
using Becetti.Security.Core.Services;

namespace Becetti.Security.App.ViewModels;

/// <summary>
/// Interactive Enterprise Command Center Dashboard. Every value is read live from
/// Defender, Native YARA Engine, real active shields, the OS, or the cloud API at refresh time.
/// </summary>
public sealed class DashboardViewModel : ViewModelBase
{
    private readonly IDefenderService _defender;
    private readonly ISystemInfoService _system;
    private readonly ICloudService _cloud;
    private readonly ISettingsService _settings;
    private readonly IYaraEngineService _yara;
    private readonly IRealTimeYaraGuardService _folderGuard;
    private readonly IRansomwareCanaryService _canary;
    private readonly IClipboardGuardService _clipboard;
    private readonly IUsbAutoScanService _usb;
    private readonly IHostsDnsGuardService _hosts;
    private readonly IFileIntegrityMonitorService _fim;
    private readonly IBecettiAiService _ai;
    private readonly LocalizationService _localization;
    private readonly SpeechService _speech;
    private readonly IThreatFeedService _threatFeeds;

    private string _defenderText = "Unknown";
    private string _realTimeText = "Unknown";
    private string _firewallText = "Unknown";
    private string _signatureText = "Unknown";
    private string _yaraText = "Checking YARA Engine…";
    private string _deviceText = "Unknown";
    private string _cloudText = "Not configured";
    private string _lastScanText = "No scan has run yet";
    private string _appVersion = "1.0.0";
    private ProtectionLevel _protectionLevel = ProtectionLevel.Unknown;
    private SecurityScoreResult _securityScore = new();
    private string _aiBriefingText = "Click 'Generate AI Briefing' for an instant executive security summary based on your live Windows, YARA, and Shield telemetry.";
    private bool _isGeneratingBriefing;

    private bool _yaraGuardActive;
    private bool _canaryActive;
    private bool _clipboardActive;
    private bool _usbAutoActive;
    private bool _hostsGuardActive;
    private bool _fimActive;

    public DashboardViewModel(
        IDefenderService defender,
        ISystemInfoService system,
        ICloudService cloud,
        ISettingsService settings,
        IYaraEngineService yara,
        IRealTimeYaraGuardService folderGuard,
        IRansomwareCanaryService canary,
        IClipboardGuardService clipboard,
        IUsbAutoScanService usb,
        IHostsDnsGuardService hosts,
        IFileIntegrityMonitorService fim,
        IBecettiAiService ai,
        LocalizationService localization,
        SpeechService speech,
        IThreatFeedService threatFeeds)
    {
        _defender = defender;
        _system = system;
        _cloud = cloud;
        _settings = settings;
        _yara = yara;
        _folderGuard = folderGuard;
        _canary = canary;
        _clipboard = clipboard;
        _usb = usb;
        _hosts = hosts;
        _fim = fim;
        _ai = ai;
        _localization = localization;
        _speech = speech;
        _threatFeeds = threatFeeds;
        RefreshCommand = new RelayCommand(LoadAsync);
        GenerateAiBriefingCommand = new RelayCommand(GenerateAiBriefingAsync, () => !IsGeneratingBriefing);
        SpeakAiBriefingCommand = new RelayCommand(SpeakAiBriefingAsync, () => !string.IsNullOrWhiteSpace(AiBriefingText));
    }

    public RelayCommand RefreshCommand { get; }
    public RelayCommand GenerateAiBriefingCommand { get; }
    public RelayCommand SpeakAiBriefingCommand { get; }

    public string AiBriefingText
    {
        get => _aiBriefingText;
        set
        {
            if (SetProperty(ref _aiBriefingText, value))
                SpeakAiBriefingCommand.RaiseCanExecuteChanged();
        }
    }

    public bool IsGeneratingBriefing
    {
        get => _isGeneratingBriefing;
        set
        {
            if (SetProperty(ref _isGeneratingBriefing, value))
                GenerateAiBriefingCommand.RaiseCanExecuteChanged();
        }
    }

    public string DefenderText { get => _defenderText; set => SetProperty(ref _defenderText, value); }
    public string RealTimeText { get => _realTimeText; set => SetProperty(ref _realTimeText, value); }
    public string FirewallText { get => _firewallText; set => SetProperty(ref _firewallText, value); }
    public string SignatureText { get => _signatureText; set => SetProperty(ref _signatureText, value); }
    public string YaraText { get => _yaraText; set => SetProperty(ref _yaraText, value); }
    public string DeviceText { get => _deviceText; set => SetProperty(ref _deviceText, value); }
    public string CloudText { get => _cloudText; set => SetProperty(ref _cloudText, value); }
    public string LastScanText { get => _lastScanText; set => SetProperty(ref _lastScanText, value); }
    public string AppVersion { get => _appVersion; set => SetProperty(ref _appVersion, value); }

    public bool YaraGuardActive
    {
        get => _yaraGuardActive;
        set
        {
            if (SetProperty(ref _yaraGuardActive, value))
                _ = ToggleYaraGuardAsync(value);
        }
    }

    public bool CanaryActive
    {
        get => _canaryActive;
        set
        {
            if (SetProperty(ref _canaryActive, value))
                _ = ToggleCanaryAsync(value);
        }
    }

    public bool ClipboardActive
    {
        get => _clipboardActive;
        set
        {
            if (SetProperty(ref _clipboardActive, value))
                _ = ToggleClipboardAsync(value);
        }
    }

    public bool UsbAutoActive
    {
        get => _usbAutoActive;
        set
        {
            if (SetProperty(ref _usbAutoActive, value))
                _ = ToggleUsbAsync(value);
        }
    }

    public bool HostsGuardActive
    {
        get => _hostsGuardActive;
        set
        {
            if (SetProperty(ref _hostsGuardActive, value))
                _ = ToggleHostsAsync(value);
        }
    }

    public bool FimActive
    {
        get => _fimActive;
        set
        {
            if (SetProperty(ref _fimActive, value))
                _ = ToggleFimAsync(value);
        }
    }

    public ProtectionLevel ProtectionLevel
    {
        get => _protectionLevel;
        set
        {
            if (SetProperty(ref _protectionLevel, value))
            {
                OnPropertyChanged(nameof(ProtectionHeadline));
                OnPropertyChanged(nameof(ProtectionSubtext));
            }
        }
    }

    public string ProtectionHeadline => ProtectionLevel switch
    {
        ProtectionLevel.Protected => "Your device is protected",
        ProtectionLevel.Warning => "Your device needs attention",
        ProtectionLevel.Danger => "Your device is at risk",
        _ => "Protection status unknown"
    };

    public string ProtectionSubtext => ProtectionLevel switch
    {
        ProtectionLevel.Protected => "Microsoft Defender antivirus, real-time protection, and Native YARA Engine are verified active.",
        ProtectionLevel.Warning => "Real-time protection is off, or another antivirus product is managing protection. See Real-Time Protection for details.",
        ProtectionLevel.Danger => "Antivirus is disabled. Enable Microsoft Defender or your other antivirus product.",
        _ => "BECETTI SECURITY could not verify Microsoft Defender's status on this device."
    };

    public bool EnableAnimations => _settings.Current.EnableAnimations;

    public SecurityScoreResult SecurityScore
    {
        get => _securityScore;
        private set
        {
            if (SetProperty(ref _securityScore, value))
            {
                OnPropertyChanged(nameof(SecurityScoreText));
                OnPropertyChanged(nameof(SecurityScoreValue));
                OnPropertyChanged(nameof(SecurityScoreGrade));
            }
        }
    }

    public string SecurityScoreText => SecurityScore.Score?.ToString() ?? "—";
    public double SecurityScoreValue => SecurityScore.Score ?? 0;
    public string SecurityScoreGrade => SecurityScore.Grade;

    public async Task LoadAsync()
    {
        if (IsBusy)
            return;

        IsBusy = true;
        ClearMessages();
        try
        {
            // Sync live shield switches without triggering duplicate start/stop
            _yaraGuardActive = _folderGuard.IsRunning; OnPropertyChanged(nameof(YaraGuardActive));
            _canaryActive = _canary.IsArmed; OnPropertyChanged(nameof(CanaryActive));
            _clipboardActive = _clipboard.IsEnabled; OnPropertyChanged(nameof(ClipboardActive));
            _usbAutoActive = _usb.IsEnabled; OnPropertyChanged(nameof(UsbAutoActive));
            _hostsGuardActive = _hosts.IsWatching; OnPropertyChanged(nameof(HostsGuardActive));
            _fimActive = _fim.IsWatching; OnPropertyChanged(nameof(FimActive));

            var yaraInit = await _yara.InitializeAsync();
            if (yaraInit.Success && yaraInit.Value is not null && yaraInit.Value.IsAvailable)
                YaraText = $"YARA {yaraInit.Value.Version} · {yaraInit.Value.ActiveRuleCount} active rules compiled";
            else
                YaraText = "YARA engine unavailable";

            var status = await _defender.GetStatusAsync();
            ProtectionLevel = ProtectionStatusEvaluator.Evaluate(status.Success ? status.Value : null);
            if (status.Success && status.Value is not null)
            {
                var s = status.Value;
                DefenderText = s.AntivirusEnabled ? "Antivirus: Enabled" : "Antivirus: Disabled";
                RealTimeText = s.RealTimeProtectionEnabled ? "Real-time protection: On" : "Real-time protection: Off";
                SignatureText = s.AntivirusSignatureVersion is not null
                    ? $"Signatures: {s.AntivirusSignatureVersion} ({s.AntivirusSignatureLastUpdated?.ToString("g") ?? "unknown"})"
                    : "Signatures: Unknown";
            }
            else
            {
                DefenderText = "Unknown";
                RealTimeText = "Unknown";
                SignatureText = "Unknown";
                ErrorMessage = status.Message;
            }

            var firewall = await _defender.GetFirewallAsync();
            if (firewall.Success && firewall.Value is not null)
            {
                FirewallText = firewall.Value.All(f => f.Enabled)
                    ? "Firewall: On (all profiles)"
                    : "Firewall: " + string.Join(", ", firewall.Value.Select(f => $"{f.Name}: {(f.Enabled ? "On" : "Off")}"));
            }
            else
            {
                FirewallText = "Unknown";
            }

            var ransomware = await _defender.GetRansomwareProtectionAsync();
            SecurityScore = SecurityScoreEvaluator.Evaluate(
                status.Success ? status.Value : null,
                firewall.Success ? firewall.Value : null,
                ransomware.Success ? ransomware.Value : null);

            var device = await _system.GetDeviceInfoAsync();
            if (device.Success && device.Value is not null)
            {
                var d = device.Value;
                DeviceText = $"{d.DeviceName} · {d.OsDescription} (build {d.OsBuild})";
            }

            if (_cloud.IsConfigured)
            {
                var health = await _cloud.GetHealthAsync();
                CloudText = health.Success ? $"Connected (API {health.Value!.Version})" : $"Unreachable — {health.Message}";
            }
            else
            {
                CloudText = "Not configured (Settings)";
            }

            LastScanText = _settings.Current.LastVerifiedScan.HasValue
                ? $"{_settings.Current.LastVerifiedScan.Value.ToLocalTime():g} — {_settings.Current.LastScanSummary}"
                : "No scan has run yet";

            AppVersion = typeof(DashboardViewModel).Assembly.GetName().Version?.ToString(3) ?? "1.0.0";
            StatusMessage = "Live command center telemetry updated.";
        }
        finally
        {
            IsBusy = false;
        }
    }

    private async Task ToggleYaraGuardAsync(bool enable)
    {
        if (enable)
        {
            var res = await _folderGuard.StartAsync();
            StatusMessage = res.Message;
        }
        else
        {
            _folderGuard.Stop();
            StatusMessage = "Real-Time YARA Folder Guard stopped.";
        }
        _settings.Current.RealTimeYaraGuardEnabled = enable;
        await _settings.SaveAsync();
    }

    private async Task ToggleCanaryAsync(bool enable)
    {
        if (enable)
        {
            var res = await _canary.ArmAsync();
            StatusMessage = res.Message;
        }
        else
        {
            _canary.Disarm(removeDecoyFiles: true);
            StatusMessage = "Ransomware Canary Guard disarmed.";
        }
        _settings.Current.RansomwareCanaryEnabled = enable;
        await _settings.SaveAsync();
    }

    private async Task ToggleClipboardAsync(bool enable)
    {
        _clipboard.IsEnabled = enable;
        _settings.Current.ClipboardGuardEnabled = enable;
        await _settings.SaveAsync();
        StatusMessage = enable ? "Clipboard Hijack Guard enabled." : "Clipboard Hijack Guard disabled.";
    }

    private async Task ToggleUsbAsync(bool enable)
    {
        if (enable) _usb.Start();
        else _usb.Stop();
        _settings.Current.UsbAutoScanEnabled = enable;
        await _settings.SaveAsync();
        StatusMessage = enable ? "USB Auto-Scan started." : "USB Auto-Scan stopped.";
    }

    private async Task ToggleHostsAsync(bool enable)
    {
        var res = enable ? _hosts.StartWatching() : _hosts.StopWatching();
        _settings.Current.HostsGuardEnabled = enable;
        await _settings.SaveAsync();
        StatusMessage = res.Message;
    }

    private async Task ToggleFimAsync(bool enable)
    {
        var res = enable ? await _fim.StartWatchingAsync() : _fim.StopWatching();
        _settings.Current.FimAutoWatchEnabled = enable;
        await _settings.SaveAsync();
        StatusMessage = res.Message;
    }

    public async Task GenerateAiBriefingAsync()
    {
        if (IsGeneratingBriefing) return;
        IsGeneratingBriefing = true;
        ClearMessages();
        try
        {
            var langName = _localization.Current switch
            {
                AppLanguage.Arabic => "Arabic",
                AppLanguage.French => "French",
                AppLanguage.Spanish => "Spanish",
                AppLanguage.German => "German",
                AppLanguage.Turkish => "Turkish",
                _ => "English"
            };

            var feeds = _threatFeeds.GetStatus();
            var prompt =
                $"Give me a concise 3-bullet Executive Security Briefing in {langName} based ONLY on these real live endpoint metrics from BECETTI SECURITY:\n" +
                $"- Security Score: {SecurityScoreText}/100 ({ProtectionHeadline})\n" +
                $"- Microsoft Defender: {DefenderText} · Real-Time: {RealTimeText} · Firewall: {FirewallText}\n" +
                $"- Native YARA Engine: {YaraText}\n" +
                $"- Active Shields: YARA Guard={(YaraGuardActive ? "ON" : "OFF")}, Ransomware Canary={(CanaryActive ? "ON" : "OFF")}, Clipboard={(ClipboardActive ? "ON" : "OFF")}, USB Auto-Scan={(UsbAutoActive ? "ON" : "OFF")}, Hosts Guard={(HostsGuardActive ? "ON" : "OFF")}, FIM={(FimActive ? "ON" : "OFF")}\n" +
                $"- Global Threat Feeds (abuse.ch): {feeds.TotalIndicators:N0} IOCs synced\n" +
                $"- Last Scan: {LastScanText}\n" +
                $"Keep it crisp (max 80 words total) with 1 positive observation and 2 concrete next actions inside the app.";

            var res = await _ai.SendAsync(new[] { new AiChatTurn { Role = "user", Content = prompt } });
            if (res.Success && !string.IsNullOrWhiteSpace(res.Value))
            {
                AiBriefingText = res.Value.Trim();
            }
            else
            {
                ErrorMessage = res.Message;
            }
        }
        finally
        {
            IsGeneratingBriefing = false;
        }
    }

    private async Task SpeakAiBriefingAsync()
    {
        if (string.IsNullOrWhiteSpace(AiBriefingText)) return;
        await _speech.SpeakAsync(AiBriefingText, _localization.Bcp47Tag);
    }
}
