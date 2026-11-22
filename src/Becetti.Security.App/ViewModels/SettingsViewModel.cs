using Becetti.Security.Core.Services;

namespace Becetti.Security.App.ViewModels;

/// <summary>Settings page: instant live language switching, cloud API URL, telemetry and alerts.</summary>
public sealed class SettingsViewModel : ViewModelBase
{
    private readonly ISettingsService _settings;
    private readonly LocalizationService _localization;
    private readonly ICloudService _cloud;

    private bool _isLoading;
    private string _apiBaseUrl = string.Empty;
    private string _language = "en";
    private bool _telemetryOptIn;
    private bool _enableAnimations = true;
    private bool _enableSounds = true;
    private string _connectionText = string.Empty;
    private string _aiApiBaseUrl = string.Empty;
    private bool _aiShareDeviceState;
    private bool _aiSaveHistory;
    private string _supportEmail = string.Empty;
    private bool _criticalAlertNotificationsEnabled = true;
    private string _criticalAlertWebhookUrl = string.Empty;
    private bool _minimizeToTrayOnClose = true;

    public SettingsViewModel(ISettingsService settings, LocalizationService localization, ICloudService cloud)
    {
        _settings = settings;
        _localization = localization;
        _cloud = cloud;
        LoadFromSettings();
        SaveCommand = new RelayCommand(SaveAsync);
        TestConnectionCommand = new RelayCommand(TestConnectionAsync);
    }

    public RelayCommand SaveCommand { get; }
    public RelayCommand TestConnectionCommand { get; }

    public string ApiBaseUrl { get => _apiBaseUrl; set => SetProperty(ref _apiBaseUrl, value); }

    public string Language
    {
        get => _language;
        set
        {
            if (SetProperty(ref _language, value))
            {
                OnPropertyChanged(nameof(IsEnglish));
                OnPropertyChanged(nameof(IsArabic));
                OnPropertyChanged(nameof(IsFrench));

                if (!_isLoading)
                    _ = ApplyLanguageImmediatelyAsync(value);
            }
        }
    }

    public bool TelemetryOptIn { get => _telemetryOptIn; set => SetProperty(ref _telemetryOptIn, value); }
    public bool EnableAnimations { get => _enableAnimations; set => SetProperty(ref _enableAnimations, value); }
    public bool EnableSounds { get => _enableSounds; set => SetProperty(ref _enableSounds, value); }
    public string ConnectionText { get => _connectionText; set => SetProperty(ref _connectionText, value); }

    public bool IsArabic { get => Language == "ar"; set { if (value) Language = "ar"; } }
    public bool IsEnglish { get => Language == "en"; set { if (value) Language = "en"; } }
    public bool IsFrench { get => Language == "fr"; set { if (value) Language = "fr"; } }

    public string AiApiBaseUrl { get => _aiApiBaseUrl; set => SetProperty(ref _aiApiBaseUrl, value); }
    public bool AiShareDeviceState { get => _aiShareDeviceState; set => SetProperty(ref _aiShareDeviceState, value); }
    public bool AiSaveHistory { get => _aiSaveHistory; set => SetProperty(ref _aiSaveHistory, value); }
    public string SupportEmail { get => _supportEmail; set => SetProperty(ref _supportEmail, value); }

    /// <summary>Local Windows notification for critical events (threat found, breach found, malicious result). On by default.</summary>
    public bool CriticalAlertNotificationsEnabled { get => _criticalAlertNotificationsEnabled; set => SetProperty(ref _criticalAlertNotificationsEnabled, value); }

    /// <summary>Optional webhook URL (Slack/Discord/generic) critical alerts are also POSTed to. Empty = disabled.</summary>
    public string CriticalAlertWebhookUrl { get => _criticalAlertWebhookUrl; set => SetProperty(ref _criticalAlertWebhookUrl, value); }

    /// <summary>When true, closing the main window hides BECETTI SECURITY to the Windows System Tray so background shields stay active.</summary>
    public bool MinimizeToTrayOnClose { get => _minimizeToTrayOnClose; set => SetProperty(ref _minimizeToTrayOnClose, value); }

    private void LoadFromSettings()
    {
        _isLoading = true;
        try
        {
            ApiBaseUrl = _settings.Current.ApiBaseUrl;
            Language = _localization.ShortCode;
            TelemetryOptIn = _settings.Current.TelemetryOptIn;
            EnableAnimations = _settings.Current.EnableAnimations;
            EnableSounds = _settings.Current.EnableSounds;
            AiApiBaseUrl = _settings.Current.AiApiBaseUrl;
            AiShareDeviceState = _settings.Current.AiShareDeviceState;
            AiSaveHistory = _settings.Current.AiSaveHistory;
            SupportEmail = _settings.Current.SupportEmail;
            CriticalAlertNotificationsEnabled = _settings.Current.CriticalAlertNotificationsEnabled;
            CriticalAlertWebhookUrl = _settings.Current.CriticalAlertWebhookUrl;
            MinimizeToTrayOnClose = _settings.Current.MinimizeToTrayOnClose;
        }
        finally
        {
            _isLoading = false;
        }
    }

    private async Task ApplyLanguageImmediatelyAsync(string code)
    {
        try
        {
            var lang = LocalizationService.ParseLanguageCode(code);
            if (lang == _localization.Current)
                return;

            await _localization.SetLanguageAsync(lang);
            App.ApplyLanguageOverride(code);

            StatusMessage = _localization.Get("SettingsLanguageApplied", "Language updated.");
        }
        catch (Exception ex)
        {
            ErrorMessage = ex.Message;
        }
    }

    public async Task SaveAsync()
    {
        if (IsBusy)
            return;

        IsBusy = true;
        ClearMessages();
        try
        {
            _settings.Current.ApiBaseUrl = ApiBaseUrl.Trim();
            _settings.Current.TelemetryOptIn = TelemetryOptIn;
            _settings.Current.EnableAnimations = EnableAnimations;
            _settings.Current.EnableSounds = EnableSounds;
            _settings.Current.AiApiBaseUrl = AiApiBaseUrl.Trim();
            _settings.Current.AiShareDeviceState = AiShareDeviceState;
            _settings.Current.AiSaveHistory = AiSaveHistory;
            _settings.Current.SupportEmail = SupportEmail.Trim();
            _settings.Current.CriticalAlertNotificationsEnabled = CriticalAlertNotificationsEnabled;
            _settings.Current.CriticalAlertWebhookUrl = CriticalAlertWebhookUrl.Trim();
            _settings.Current.MinimizeToTrayOnClose = MinimizeToTrayOnClose;
            await _settings.SaveAsync();

            var language = LocalizationService.ParseLanguageCode(Language);
            await _localization.SetLanguageAsync(language);
            App.ApplyLanguageOverride(Language);

            StatusMessage = _localization.Get("SettingsSavedMessage", "Settings saved.");
        }
        finally
        {
            IsBusy = false;
        }
    }

    public async Task TestConnectionAsync()
    {
        if (IsBusy)
            return;

        IsBusy = true;
        ClearMessages();
        try
        {
            _settings.Current.ApiBaseUrl = ApiBaseUrl.Trim();
            await _settings.SaveAsync();

            var health = await _cloud.GetHealthAsync();
            if (health.Success && health.Value is not null)
            {
                ConnectionText = $"Connected — API {health.Value.Version}";
                StatusMessage = "Connection test succeeded.";
            }
            else
            {
                ConnectionText = "Not connected";
                ErrorMessage = health.Message;
            }
        }
        finally
        {
            IsBusy = false;
        }
    }
}
