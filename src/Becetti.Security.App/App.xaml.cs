using Becetti.Security.App.ViewModels;
using Becetti.Security.Core.Services;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;

namespace Becetti.Security.App;

/// <summary>
/// Application entry point. Wires up dependency injection, loads persisted
/// settings and restores the cloud session before showing the main window.
/// </summary>
public partial class App : Application
{
    public static IServiceProvider Services { get; private set; } = null!;

    public static MainWindow? MainWindow { get; private set; }

    private Window? _window;

    public App()
    {
        InitializeComponent();
    }

    protected override async void OnLaunched(LaunchActivatedEventArgs args)
    {
        var services = new ServiceCollection();
        services.AddSingleton<ISettingsService, SettingsService>();
        services.AddSingleton<ITokenStore, TokenStore>();
        services.AddSingleton<IDefenderService, DefenderService>();
        services.AddSingleton<ISystemInfoService, SystemInfoService>();
        services.AddSingleton<IPcHealthService, PcHealthService>();
        services.AddSingleton<IStartupManagerService, StartupManagerService>();
        services.AddSingleton<ISoftwareManagerService, SoftwareManagerService>();
        services.AddSingleton<IDriverMonitorService, DriverMonitorService>();
        services.AddSingleton<IUsbProtectionService, UsbProtectionService>();
        services.AddSingleton<IEventLogService, EventLogService>();
        services.AddSingleton<LocalizationService>();
        services.AddSingleton<Services.SoundService>();
        services.AddSingleton<Services.SpeechService>();
        // Real-device testing surfaced timeouts reaching the BECETTI AI backend on a
        // machine where a normal browser worked fine. HttpClient's default SocketsHttpHandler
        // has no explicit connect timeout, so when a restrictive firewall/antivirus or a flaky
        // network silently drops the TCP/TLS handshake instead of refusing it outright, the
        // whole request can sit doing nothing until the much longer per-request timeout below
        // finally gives up. An explicit, shorter ConnectTimeout makes that specific failure
        // mode fail fast with a clear, distinguishable error instead of a long silent hang.
        static SocketsHttpHandler NetworkResilientHandler() => new()
        {
            ConnectTimeout = TimeSpan.FromSeconds(10),
            PooledConnectionLifetime = TimeSpan.FromMinutes(5)
        };

        services.AddHttpClient<ICloudService, CloudService>().ConfigurePrimaryHttpMessageHandler(NetworkResilientHandler);
        services.AddHttpClient<IBecettiAiService, BecettiAiService>().ConfigurePrimaryHttpMessageHandler(NetworkResilientHandler);

        services.AddTransient<DashboardViewModel>();
        services.AddTransient<ScanViewModel>();
        services.AddTransient<ProtectionViewModel>();
        services.AddTransient<CloudViewModel>();
        services.AddTransient<ThreatsViewModel>();
        services.AddTransient<PrivacyViewModel>();
        services.AddTransient<HistoryViewModel>();
        services.AddTransient<UpdatesViewModel>();
        services.AddTransient<SettingsViewModel>();
        services.AddTransient<AboutViewModel>();
        services.AddTransient<BecettiAiViewModel>();
        services.AddTransient<ContactViewModel>();
        services.AddTransient<RansomwareViewModel>();
        services.AddTransient<PcHealthViewModel>();
        services.AddTransient<StartupManagerViewModel>();
        services.AddTransient<SoftwareManagerViewModel>();
        services.AddTransient<DriverMonitorViewModel>();
        services.AddTransient<EmergencyCenterViewModel>();
        services.AddTransient<UsbProtectionViewModel>();

        Services = services.BuildServiceProvider();

        var settings = Services.GetRequiredService<ISettingsService>();
        await settings.LoadAsync();

        // Apply the persisted UI language before any window/resw lookup happens,
        // so the correct Strings/<culture>/Resources.resw is the one resolved.
        ApplyLanguageOverride(settings.Current.Language);

        var cloud = Services.GetRequiredService<ICloudService>();
        if (cloud is CloudService concreteCloud)
            await concreteCloud.RestoreSessionAsync();

        var mainWindow = new MainWindow();
        _window = mainWindow;
        MainWindow = mainWindow;
        mainWindow.Activate();
    }

    /// <summary>
    /// Sets the resource language actually used to resolve x:Uid-based resw strings.
    /// Must run before any XAML is loaded for a language switch to take effect.
    /// </summary>
    private static void ApplyLanguageOverride(string languageCode)
    {
        var bcp47 = languageCode switch
        {
            "ar" => "ar-SA",
            "fr" => "fr-FR",
            _ => "en-US"
        };

        try
        {
            Windows.Globalization.ApplicationLanguages.PrimaryLanguageOverride = bcp47;
        }
        catch
        {
            // Best-effort: if the override can't be set (e.g. unpackaged dev run),
            // the app falls back to the OS-selected display language.
        }
    }
}
