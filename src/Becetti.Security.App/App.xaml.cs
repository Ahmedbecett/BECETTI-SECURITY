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
        services.AddSingleton<IEventLogService, EventLogService>();
        services.AddSingleton<LocalizationService>();
        services.AddSingleton<Services.SoundService>();
        services.AddHttpClient<ICloudService, CloudService>();

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

        Services = services.BuildServiceProvider();

        var settings = Services.GetRequiredService<ISettingsService>();
        await settings.LoadAsync();

        var cloud = Services.GetRequiredService<ICloudService>();
        if (cloud is CloudService concreteCloud)
            await concreteCloud.RestoreSessionAsync();

        var mainWindow = new MainWindow();
        _window = mainWindow;
        MainWindow = mainWindow;
        mainWindow.Activate();
    }
}
