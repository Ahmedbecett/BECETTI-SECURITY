namespace Becetti.Security.Core.Services;

public enum AppLanguage
{
    English,
    Arabic
}

/// <summary>Tracks the selected UI language and text direction (RTL for Arabic).</summary>
public sealed class LocalizationService
{
    private readonly ISettingsService _settings;

    public LocalizationService(ISettingsService settings)
    {
        _settings = settings;
        Current = settings.Current.Language == "ar" ? AppLanguage.Arabic : AppLanguage.English;
    }

    public AppLanguage Current { get; private set; }
    public bool IsRtl => Current == AppLanguage.Arabic;
    public string FlowDirection => IsRtl ? "RightToLeft" : "LeftToRight";

    public event EventHandler? LanguageChanged;

    public async Task SetLanguageAsync(AppLanguage language, CancellationToken ct = default)
    {
        Current = language;
        _settings.Current.Language = language == AppLanguage.Arabic ? "ar" : "en";
        await _settings.SaveAsync(ct).ConfigureAwait(false);
        LanguageChanged?.Invoke(this, EventArgs.Empty);
    }
}
