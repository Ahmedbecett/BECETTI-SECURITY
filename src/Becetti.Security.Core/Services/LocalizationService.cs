using System.Globalization;
using System.Reflection;
using System.Xml.Linq;

namespace Becetti.Security.Core.Services;

public enum AppLanguage
{
    English,
    Arabic,
    French,
    Spanish,
    German,
    Turkish
}

/// <summary>
/// Tracks the selected UI language, text direction (RTL for Arabic), and provides
/// instant live string resolution from the single-source-of-truth .resw catalogs
/// (en-US, ar-SA, fr-FR, es-ES, de-DE, tr-TR) embedded into Core — so changing language
/// updates the entire UI immediately without requiring an app restart.
/// </summary>
public sealed class LocalizationService
{
    private readonly ISettingsService _settings;
    private readonly Dictionary<AppLanguage, Dictionary<string, string>> _catalogs;

    public LocalizationService(ISettingsService settings)
    {
        _settings = settings;
        _catalogs = LoadEmbeddedCatalogs();
        SyncFromSettings();
    }

    public AppLanguage Current { get; private set; }
    public bool IsRtl => Current == AppLanguage.Arabic;
    public string FlowDirection => IsRtl ? "RightToLeft" : "LeftToRight";

    public string Bcp47Tag => Current switch
    {
        AppLanguage.Arabic => "ar-SA",
        AppLanguage.French => "fr-FR",
        AppLanguage.Spanish => "es-ES",
        AppLanguage.German => "de-DE",
        AppLanguage.Turkish => "tr-TR",
        _ => "en-US"
    };

    public string ShortCode => Current switch
    {
        AppLanguage.Arabic => "ar",
        AppLanguage.French => "fr",
        AppLanguage.Spanish => "es",
        AppLanguage.German => "de",
        AppLanguage.Turkish => "tr",
        _ => "en"
    };

    public event EventHandler? LanguageChanged;

    /// <summary>Synchronizes Current with <see cref="ISettingsService.Current"/> after settings load.</summary>
    public void SyncFromSettings()
    {
        Current = ParseLanguageCode(_settings.Current.Language);
        ApplyThreadCulture(Bcp47Tag);
    }

    public static AppLanguage ParseLanguageCode(string? code) =>
        (code ?? "en").Trim().ToLowerInvariant() switch
        {
            "ar" or "ar-sa" => AppLanguage.Arabic,
            "fr" or "fr-fr" => AppLanguage.French,
            "es" or "es-es" => AppLanguage.Spanish,
            "de" or "de-de" => AppLanguage.German,
            "tr" or "tr-tr" => AppLanguage.Turkish,
            _ => AppLanguage.English
        };

    public async Task SetLanguageAsync(AppLanguage language, CancellationToken ct = default)
    {
        var changed = Current != language;
        Current = language;
        _settings.Current.Language = ShortCode;
        ApplyThreadCulture(Bcp47Tag);
        await _settings.SaveAsync(ct).ConfigureAwait(false);
        if (changed)
            LanguageChanged?.Invoke(this, EventArgs.Empty);
    }

    /// <summary>Looks up a localized string by full resource key (e.g. "NavScan.Content" or "AppTitle").</summary>
    public string Get(string key, string? fallback = null)
    {
        if (string.IsNullOrWhiteSpace(key))
            return fallback ?? string.Empty;

        if (_catalogs.TryGetValue(Current, out var dict) && dict.TryGetValue(key, out var val))
            return val;

        if (Current != AppLanguage.English &&
            _catalogs.TryGetValue(AppLanguage.English, out var en) &&
            en.TryGetValue(key, out var enVal))
        {
            return enVal;
        }

        return fallback ?? key;
    }

    /// <summary>Looks up a localized property value for an x:Uid (e.g. uid="TitleScan", property="Text").</summary>
    public string? TryGet(string uid, string property)
    {
        if (string.IsNullOrWhiteSpace(uid) || string.IsNullOrWhiteSpace(property))
            return null;

        var key = $"{uid}.{property}";
        if (_catalogs.TryGetValue(Current, out var dict) && dict.TryGetValue(key, out var val))
            return val;

        if (Current != AppLanguage.English &&
            _catalogs.TryGetValue(AppLanguage.English, out var en) &&
            en.TryGetValue(key, out var enVal))
        {
            return enVal;
        }

        return null;
    }

    /// <summary>Returns all loaded keys for a given language (used by localization parity tests).</summary>
    public IReadOnlyCollection<string> GetKeys(AppLanguage language) =>
        _catalogs.TryGetValue(language, out var dict) ? dict.Keys : Array.Empty<string>();

    private static void ApplyThreadCulture(string bcp47)
    {
        try
        {
            var culture = new CultureInfo(bcp47);
            CultureInfo.DefaultThreadCurrentUICulture = culture;
            CultureInfo.CurrentUICulture = culture;
        }
        catch
        {
            // Non-fatal on minimal environments
        }
    }

    private static Dictionary<AppLanguage, Dictionary<string, string>> LoadEmbeddedCatalogs()
    {
        var assembly = typeof(LocalizationService).Assembly;
        return new Dictionary<AppLanguage, Dictionary<string, string>>
        {
            [AppLanguage.English] = LoadResw(assembly, "Becetti.Security.Core.Strings.en-US.resw"),
            [AppLanguage.Arabic] = LoadResw(assembly, "Becetti.Security.Core.Strings.ar-SA.resw"),
            [AppLanguage.French] = LoadResw(assembly, "Becetti.Security.Core.Strings.fr-FR.resw"),
            [AppLanguage.Spanish] = LoadResw(assembly, "Becetti.Security.Core.Strings.es-ES.resw"),
            [AppLanguage.German] = LoadResw(assembly, "Becetti.Security.Core.Strings.de-DE.resw"),
            [AppLanguage.Turkish] = LoadResw(assembly, "Becetti.Security.Core.Strings.tr-TR.resw")
        };
    }

    private static Dictionary<string, string> LoadResw(Assembly assembly, string resourceName)
    {
        var map = new Dictionary<string, string>(StringComparer.Ordinal);
        using var stream = assembly.GetManifestResourceStream(resourceName);
        if (stream is null)
            return map;

        var doc = XDocument.Load(stream);
        var root = doc.Root;
        if (root is null)
            return map;

        foreach (var data in root.Elements("data"))
        {
            var name = data.Attribute("name")?.Value;
            var value = data.Element("value")?.Value;
            if (!string.IsNullOrWhiteSpace(name) && value is not null)
                map[name] = value;
        }

        return map;
    }
}
