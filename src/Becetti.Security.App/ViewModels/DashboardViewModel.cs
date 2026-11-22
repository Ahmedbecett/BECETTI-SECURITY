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
        IFileIntegrityMonitorService fim)
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
        RefreshCommand = new RelayCommand(LoadAsync);
    }

    public RelayCommand RefreshCommand { get; }

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
}
