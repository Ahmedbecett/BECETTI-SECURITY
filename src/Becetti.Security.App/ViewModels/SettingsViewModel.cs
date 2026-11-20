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
    public string Language { get => _language; set => SetProperty(ref _language, value); }

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
    public string ConnectionText { get => _connectionText; set => SetProperty(ref _connectionText, value); }

    public bool IsArabic => Language == "ar";
    public bool IsEnglish => Language == "en";

    private void LoadFromSettings()
    {
        ApiBaseUrl = _settings.Current.ApiBaseUrl;
        Language = _settings.Current.Language;
        Theme = _settings.Current.Theme;
        TelemetryOptIn = _settings.Current.TelemetryOptIn;
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
