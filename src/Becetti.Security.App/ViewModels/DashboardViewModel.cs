using Becetti.Security.Core.Models;
using Becetti.Security.Core.Services;

namespace Becetti.Security.App.ViewModels;

/// <summary>
/// Security center dashboard. Every value is read live from Defender, the OS
/// or the cloud API at refresh time. Unknown states are shown as "Unknown".
/// </summary>
public sealed class DashboardViewModel : ViewModelBase
{
    private readonly IDefenderService _defender;
    private readonly ISystemInfoService _system;
    private readonly ICloudService _cloud;
    private readonly ISettingsService _settings;

    private string _defenderText = "Unknown";
    private string _realTimeText = "Unknown";
    private string _firewallText = "Unknown";
    private string _signatureText = "Unknown";
    private string _deviceText = "Unknown";
    private string _cloudText = "Not configured";
    private string _lastScanText = "No scan has run yet";
    private string _appVersion = "1.0.0";
    private ProtectionLevel _protectionLevel = ProtectionLevel.Unknown;
    private SecurityScoreResult _securityScore = new();

    public DashboardViewModel(IDefenderService defender, ISystemInfoService system, ICloudService cloud, ISettingsService settings)
    {
        _defender = defender;
        _system = system;
        _cloud = cloud;
        _settings = settings;
        RefreshCommand = new RelayCommand(LoadAsync);
    }

    public RelayCommand RefreshCommand { get; }

    public string DefenderText { get => _defenderText; set => SetProperty(ref _defenderText, value); }
    public string RealTimeText { get => _realTimeText; set => SetProperty(ref _realTimeText, value); }
    public string FirewallText { get => _firewallText; set => SetProperty(ref _firewallText, value); }
    public string SignatureText { get => _signatureText; set => SetProperty(ref _signatureText, value); }
    public string DeviceText { get => _deviceText; set => SetProperty(ref _deviceText, value); }
    public string CloudText { get => _cloudText; set => SetProperty(ref _cloudText, value); }
    public string LastScanText { get => _lastScanText; set => SetProperty(ref _lastScanText, value); }
    public string AppVersion { get => _appVersion; set => SetProperty(ref _appVersion, value); }

    /// <summary>Aggregate status derived only from the verified DefenderStatus just read — never guessed.</summary>
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
        ProtectionLevel.Protected => "Microsoft Defender antivirus and real-time protection are verified active.",
        ProtectionLevel.Warning => "Real-time protection is off, or another antivirus product is managing protection. See Real-Time Protection for details.",
        ProtectionLevel.Danger => "Antivirus is disabled. Enable Microsoft Defender or your other antivirus product.",
        _ => "BECETTI SECURITY could not verify Microsoft Defender's status on this device."
    };

    public bool EnableAnimations => _settings.Current.EnableAnimations;

    /// <summary>0-100 score computed fresh from this load's own verified Defender/firewall/ransomware reads.</summary>
    public SecurityScoreResult SecurityScore
    {
        get => _securityScore;
        private set
        {
            if (SetProperty(ref _securityScore, value))
            {
                OnPropertyChanged(nameof(SecurityScoreText));
                OnPropertyChanged(nameof(SecurityScoreGrade));
            }
        }
    }

    public string SecurityScoreText => SecurityScore.Score?.ToString() ?? "—";
    public string SecurityScoreGrade => SecurityScore.Grade;

    public async Task LoadAsync()
    {
        if (IsBusy)
            return;

        IsBusy = true;
        ClearMessages();
        try
        {
            var status = await _defender.GetStatusAsync();
            ProtectionLevel = ProtectionStatusEvaluator.Evaluate(status.Success ? status.Value : null);
            if (status.Success && status.Value is not null)
            {
                var s = status.Value;
                DefenderText = s.AntivirusEnabled ? "Antivirus: Enabled" : "Antivirus: Disabled";
                RealTimeText = s.RealTimeProtectionEnabled ? "Real-time protection: On" : "Real-time protection: Off";
                SignatureText = s.AntivirusSignatureVersion is not null
                    ? $"Signatures: {s.AntivirusSignatureVersion} (updated {s.AntivirusSignatureLastUpdated?.ToString("g") ?? "unknown"})"
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
                    : "Firewall: Check profiles — " + string.Join(", ", firewall.Value.Select(f => $"{f.Name}: {(f.Enabled ? "On" : "Off")}"));
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
                CloudText = health.Success ? $"Cloud: Connected (API {health.Value!.Version})" : $"Cloud: Unreachable — {health.Message}";
            }
            else
            {
                CloudText = "Cloud: Not configured (set API URL in Settings)";
            }

            var lastScan = _settings.Current.LastVerifiedScan;
            LastScanText = lastScan.HasValue
                ? $"Last verified scan: {lastScan.Value:yyyy-MM-dd HH:mm} — {_settings.Current.LastScanSummary}"
                : "No scan has run yet";

            StatusMessage = "Dashboard refreshed from live system checks.";
        }
        finally
        {
            IsBusy = false;
        }
    }
}
