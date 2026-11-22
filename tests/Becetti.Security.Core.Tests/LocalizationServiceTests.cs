using Becetti.Security.Core.Services;

namespace Becetti.Security.Core.Tests;

/// <summary>
/// Verifies instant live localization across English (en-US), Arabic (ar-SA),
/// and French (fr-FR), embedded .resw key parity, RTL flagging, persistence,
/// and live LanguageChanged notifications.
/// </summary>
public sealed class LocalizationServiceTests : IDisposable
{
    private readonly string _tempDir;

    public LocalizationServiceTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "becetti-loc-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_tempDir))
                Directory.Delete(_tempDir, recursive: true);
        }
        catch
        {
            // Ignore cleanup errors
        }
    }

    [Fact]
    public void EmbeddedCatalogs_AllThreeLanguagesLoadedWithFullKeyParity()
    {
        var settings = new SettingsService(_tempDir);
        var loc = new LocalizationService(settings);

        var enKeys = loc.GetKeys(AppLanguage.English);
        var arKeys = loc.GetKeys(AppLanguage.Arabic);
        var frKeys = loc.GetKeys(AppLanguage.French);

        Assert.True(enKeys.Count >= 300, $"Expected >= 300 English keys, got {enKeys.Count}");
        Assert.Equal(enKeys.Count, arKeys.Count);
        Assert.Equal(enKeys.Count, frKeys.Count);

        var enSet = new HashSet<string>(enKeys, StringComparer.Ordinal);
        Assert.All(arKeys, k => Assert.Contains(k, enSet));
        Assert.All(frKeys, k => Assert.Contains(k, enSet));
    }

    [Fact]
    public async Task SetLanguageAsync_SwitchesCatalogRtlAndRaisesEventImmediately()
    {
        var settings = new SettingsService(_tempDir);
        var loc = new LocalizationService(settings);

        var events = new List<AppLanguage>();
        loc.LanguageChanged += (_, lang) => events.Add(lang);

        // Start in English
        await loc.SetLanguageAsync(AppLanguage.English);
        Assert.False(loc.IsRtl);
        Assert.Equal("en-US", loc.CultureName);
        Assert.Equal("Settings", loc.Get("TitleSettings.Text"));
        Assert.Equal("YARA Engine", loc.Get("NavYara.Content"));

        // Switch live to Arabic -> RTL = true & Arabic strings returned immediately
        await loc.SetLanguageAsync(AppLanguage.Arabic);
        Assert.True(loc.IsRtl);
        Assert.Equal("ar-SA", loc.CultureName);
        Assert.Equal("ar", settings.Current.Language);
        Assert.Equal("الإعدادات", loc.Get("TitleSettings.Text"));
        Assert.NotEqual("YARA Engine", loc.Get("NavYara.Content"));

        // Switch live to French -> RTL = false & French strings returned immediately
        await loc.SetLanguageAsync(AppLanguage.French);
        Assert.False(loc.IsRtl);
        Assert.Equal("fr-FR", loc.CultureName);
        Assert.Equal("fr", settings.Current.Language);
        Assert.Equal("Paramètres", loc.Get("TitleSettings.Text"));
        Assert.Equal("Moteur YARA", loc.Get("NavYara.Content"));

        Assert.Contains(AppLanguage.Arabic, events);
        Assert.Contains(AppLanguage.French, events);
    }

    [Fact]
    public async Task SyncFromSettings_RestoresPersistedLanguageAfterLoad()
    {
        var settings = new SettingsService(_tempDir);
        settings.Current.Language = "ar";
        await settings.SaveAsync();

        var reloaded = new SettingsService(_tempDir);
        await reloaded.LoadAsync();
        var loc = new LocalizationService(reloaded);
        loc.SyncFromSettings();

        Assert.Equal(AppLanguage.Arabic, loc.Current);
        Assert.True(loc.IsRtl);
        Assert.Equal("الإعدادات", loc.Get("TitleSettings.Text"));
    }
}
