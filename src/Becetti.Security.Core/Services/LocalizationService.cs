namespace Becetti.Security.Core.Services;

public enum AppLanguage
{
    English,
    Arabic,
    French
}

/// <summary>Tracks the selected UI language and text direction (RTL for Arabic).</summary>
public sealed class LocalizationService
{
    private readonly ISettingsService _settings;

    public LocalizationService(ISettingsService settings)
    {
        _settings = settings;
        Current = settings.Current.Language switch
        {
            "ar" => AppLanguage.Arabic,
            "fr" => AppLanguage.French,
            _ => AppLanguage.English
        };
    }

    public AppLanguage Current { get; private set; }
    public bool IsRtl => Current == AppLanguage.Arabic;
    public string FlowDirection => IsRtl ? "RightToLeft" : "LeftToRight";

    public event EventHandler? LanguageChanged;

    public async Task SetLanguageAsync(AppLanguage language, CancellationToken ct = default)
    {
        Current = language;
        _settings.Current.Language = language switch
        {
            AppLanguage.Arabic => "ar",
            AppLanguage.French => "fr",
            _ => "en"
        };
        await _settings.SaveAsync(ct).ConfigureAwait(false);
        LanguageChanged?.Invoke(this, EventArgs.Empty);
    }
}
