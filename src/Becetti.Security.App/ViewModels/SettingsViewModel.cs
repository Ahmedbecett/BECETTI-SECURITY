using Becetti.Security.Core.Services;

namespace Becetti.Security.App.ViewModels;

/// <summary>Settings page: language, cloud API URL, theme and telemetry opt-in.</summary>
public sealed class SettingsViewModel : ViewModelBase
{
    private readonly ISettingsService _settings;
    private readonly LocalizationService _localization;
    private readonly ICloudService _cloud;

    private string _apiBaseUrl = string.Empty;
    private string _language = "en";
    private string _theme = "dark";
    private bool _telemetryOptIn;
    private bool _enableAnimations = true;
    private bool _enableSounds = true;
    private string _connectionText = string.Empty;

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
            }
        }
    }

    public string Theme
    {
        get => _theme;
        set
        {
            if (SetProperty(ref _theme, value))
            {
                OnPropertyChanged(nameof(IsDark));
                OnPropertyChanged(nameof(IsLight));
                OnPropertyChanged(nameof(IsSystem));
            }
        }
    }

    public bool IsDark { get => Theme == "dark"; set { if (value) Theme = "dark"; } }
    public bool IsLight { get => Theme == "light"; set { if (value) Theme = "light"; } }
    public bool IsSystem { get => Theme == "system"; set { if (value) Theme = "system"; } }
    public bool TelemetryOptIn { get => _telemetryOptIn; set => SetProperty(ref _telemetryOptIn, value); }
    public bool EnableAnimations { get => _enableAnimations; set => SetProperty(ref _enableAnimations, value); }
    public bool EnableSounds { get => _enableSounds; set => SetProperty(ref _enableSounds, value); }
    public string ConnectionText { get => _connectionText; set => SetProperty(ref _connectionText, value); }

    public bool IsArabic { get => Language == "ar"; set { if (value) Language = "ar"; } }
    public bool IsEnglish { get => Language == "en"; set { if (value) Language = "en"; } }

    private void LoadFromSettings()
    {
        ApiBaseUrl = _settings.Current.ApiBaseUrl;
        Language = _settings.Current.Language;
        Theme = _settings.Current.Theme;
        TelemetryOptIn = _settings.Current.TelemetryOptIn;
        EnableAnimations = _settings.Current.EnableAnimations;
        EnableSounds = _settings.Current.EnableSounds;
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
            _settings.Current.Theme = Theme;
            _settings.Current.TelemetryOptIn = TelemetryOptIn;
            _settings.Current.EnableAnimations = EnableAnimations;
            _settings.Current.EnableSounds = EnableSounds;
            await _settings.SaveAsync();

            var language = Language == "ar" ? AppLanguage.Arabic : AppLanguage.English;
            await _localization.SetLanguageAsync(language);

            StatusMessage = "Settings saved.";
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
