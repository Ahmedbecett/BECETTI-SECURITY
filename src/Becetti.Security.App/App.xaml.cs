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
        UnhandledException += OnAppUnhandledException;
    }

    private void OnAppUnhandledException(object sender, Microsoft.UI.Xaml.UnhandledExceptionEventArgs e)
    {
        try
        {
            System.Diagnostics.Debug.WriteLine($"[BECETTI UnhandledException] {e.Exception}");
            var events = Services?.GetService<IEventLogService>();
            if (events is not null)
                _ = events.RecordAsync("AppUnhandledException", e.Message ?? e.Exception?.Message ?? "Unexpected UI exception", false);
        }
        catch { }

        // Keep the security dashboard alive on recoverable UI exceptions
        e.Handled = true;
    }

    protected override async void OnLaunched(LaunchActivatedEventArgs args)
    {
        try
        {
            await InitializeAndLaunchAsync();
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[BECETTI LaunchError] {ex}");
        }
    }

    private async Task InitializeAndLaunchAsync()
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
        services.AddSingleton<INetworkMonitorService, NetworkMonitorService>();
        services.AddSingleton<IPlatformSecurityService, PlatformSecurityService>();
        services.AddSingleton<IVulnerabilityAdvisorService, VulnerabilityAdvisorService>();
        services.AddSingleton<IBrowserSecurityService, BrowserSecurityService>();
        services.AddSingleton<ISecurityReportService, SecurityReportService>();
        services.AddSingleton<ICloudSyncService, CloudSyncService>();
        services.AddSingleton<IScheduledScanService, ScheduledScanService>();
        services.AddSingleton<IBackupAdvisorService, BackupAdvisorService>();
        services.AddSingleton<IWifiSecurityService, WifiSecurityService>();
        services.AddSingleton<IKnowledgeBaseService, KnowledgeBaseService>();
        services.AddSingleton<IEventLogService, EventLogService>();
        services.AddSingleton<IThreatIntelHistoryService, ThreatIntelHistoryService>();
        services.AddSingleton<IDataBreachHistoryService, DataBreachHistoryService>();
        services.AddSingleton<IIpReputationHistoryService, IpReputationHistoryService>();
        services.AddSingleton<IFileShredderService, FileShredderService>();
        services.AddSingleton<ISecureVaultService, SecureVaultService>();
        services.AddSingleton<IParentalControlService, ParentalControlService>();
        services.AddSingleton<IGamePerformanceModeService, GamePerformanceModeService>();
        services.AddSingleton<IQuarantineService, QuarantineService>();
        services.AddSingleton<IFileForensicsService, FileForensicsService>();
        services.AddSingleton<IRealTimeYaraGuardService, RealTimeYaraGuardService>();
        services.AddSingleton<IRansomwareCanaryService, RansomwareCanaryService>();
        services.AddSingleton<IClipboardGuardService, ClipboardGuardService>();
        services.AddSingleton<IUsbAutoScanService, UsbAutoScanService>();
        services.AddSingleton<IScheduledYaraUpdateService, ScheduledYaraUpdateService>();
        services.AddSingleton<IExplorerContextMenuService, ExplorerContextMenuService>();
        services.AddSingleton<IPerAppFirewallService, PerAppFirewallService>();
        services.AddSingleton<IPersistenceHunterService, PersistenceHunterService>();
        services.AddSingleton<IHostsDnsGuardService, HostsDnsGuardService>();
        services.AddSingleton<ICameraMicAuditorService, CameraMicAuditorService>();
        services.AddSingleton<IScriptCommandAuditorService, ScriptCommandAuditorService>();
        services.AddSingleton<IUrlPhishingInspectorService, UrlPhishingInspectorService>();
        services.AddSingleton<INetworkKillSwitchService, NetworkKillSwitchService>();
        services.AddSingleton<IIncidentEvidenceService, IncidentEvidenceService>();
        services.AddSingleton<IFileIntegrityMonitorService, FileIntegrityMonitorService>();
        services.AddSingleton<IWindowsHardeningService, WindowsHardeningService>();
        services.AddSingleton<IBrowserExtensionAuditorService, BrowserExtensionAuditorService>();
        services.AddSingleton<ISoftwareUpdateAuditorService, SoftwareUpdateAuditorService>();
        services.AddSingleton<IWifiArpGuardService, WifiArpGuardService>();
        services.AddSingleton<IProcessDllInspectorService, ProcessDllInspectorService>();
        services.AddSingleton<ISecureShredderService, SecureShredderService>();
        services.AddSingleton<IScanSchedulerService, ScanSchedulerService>();
        services.AddSingleton<IExecutiveHtmlReportService, ExecutiveHtmlReportService>();
        services.AddSingleton<IAppLockService, AppLockService>();
        services.AddSingleton<IWindowsPrivacyHardenerService, WindowsPrivacyHardenerService>();
        // 12-Module Enterprise Mega-Suite Core Services
        services.AddSingleton<ILocalSiemService, LocalSiemService>();
        services.AddSingleton<ILanDiscoveryService, LanDiscoveryService>();
        services.AddSingleton<IPrivacyCleanerService, PrivacyCleanerService>();
        services.AddSingleton<ISoarPlaybookService, SoarPlaybookService>();
        services.AddSingleton<IRootCertAuditorService, RootCertAuditorService>();
        services.AddSingleton<IVaultProService, VaultProService>();
        services.AddSingleton<IEmailForensicsService, EmailForensicsService>();
        services.AddSingleton<IProcessTreeHunterService, ProcessTreeHunterService>();
        services.AddSingleton<ISigmaRuleScannerService, SigmaRuleScannerService>();
        services.AddSingleton<INetworkDnsMonitorService, NetworkDnsMonitorService>();
        services.AddSingleton<IFleetDashboardService, FleetDashboardService>();
        services.AddSingleton<IComplianceCenterService, ComplianceCenterService>();
        services.AddSingleton<Services.IAiTriageNavigator, Services.AiTriageNavigator>();
        services.AddSingleton<LocalizationService>();
        services.AddSingleton<Services.SystemTrayService>();
        services.AddSingleton<Services.SoundService>();
        services.AddSingleton<Services.SpeechService>();
        services.AddSingleton<Services.NotificationService>();
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
        services.AddHttpClient<IYaraEngineService, YaraEngineService>().ConfigurePrimaryHttpMessageHandler(NetworkResilientHandler);
        services.AddHttpClient<IThreatIntelligenceService, ThreatIntelligenceService>().ConfigurePrimaryHttpMessageHandler(NetworkResilientHandler);
        services.AddHttpClient<IDataBreachService, DataBreachService>().ConfigurePrimaryHttpMessageHandler(NetworkResilientHandler);
        services.AddHttpClient<IIpReputationService, IpReputationService>().ConfigurePrimaryHttpMessageHandler(NetworkResilientHandler);
        services.AddHttpClient<IPasswordBreachService, PasswordBreachService>().ConfigurePrimaryHttpMessageHandler(NetworkResilientHandler);
        services.AddHttpClient<IThreatFeedService, ThreatFeedService>().ConfigurePrimaryHttpMessageHandler(NetworkResilientHandler);
        services.AddHttpClient<IOutboundRadarService, OutboundRadarService>().ConfigurePrimaryHttpMessageHandler(NetworkResilientHandler);
        services.AddHttpClient<IAppUpdaterService, AppUpdaterService>().ConfigurePrimaryHttpMessageHandler(NetworkResilientHandler);
        services.AddHttpClient<IMultiEngineAvService, MultiEngineAvService>().ConfigurePrimaryHttpMessageHandler(NetworkResilientHandler);
        services.AddHttpClient<IDomainHostingIntelService, DomainHostingIntelService>().ConfigurePrimaryHttpMessageHandler(NetworkResilientHandler);

        services.AddTransient<DashboardViewModel>();
        services.AddTransient<ScanViewModel>();
        services.AddTransient<YaraScannerViewModel>();
        services.AddTransient<MultiEngineAvViewModel>();
        services.AddTransient<DomainHostingViewModel>();
        services.AddTransient<AdvancedDefenseViewModel>();
        services.AddTransient<EdrCenterViewModel>();
        services.AddTransient<ProactiveDefenseViewModel>();
        services.AddTransient<GlobalIntelViewModel>();
        services.AddTransient<SocOperationsViewModel>();
        services.AddTransient<InfrastructureComplianceViewModel>();
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
        services.AddTransient<NetworkMonitorViewModel>();
        services.AddTransient<VulnerabilityAdvisorViewModel>();
        services.AddTransient<BrowserSecurityViewModel>();
        services.AddTransient<SecurityReportsViewModel>();
        services.AddTransient<IdentityProtectionViewModel>();
        services.AddTransient<CloudSyncViewModel>();
        services.AddTransient<ScheduledScanViewModel>();
        services.AddTransient<BackupAdvisorViewModel>();
        services.AddTransient<WifiSecurityViewModel>();
        services.AddTransient<KnowledgeBaseViewModel>();
        services.AddTransient<ThreatIntelligenceViewModel>();
        services.AddTransient<DataBreachViewModel>();
        services.AddTransient<IpReputationViewModel>();
        services.AddTransient<FileShredderViewModel>();
        services.AddTransient<SecureVaultViewModel>();
        services.AddTransient<ParentalControlViewModel>();
        services.AddTransient<GamePerformanceModeViewModel>();

        Services = services.BuildServiceProvider();

        var settings = Services.GetRequiredService<ISettingsService>();
        await settings.LoadAsync();

        // Apply the persisted UI language before any window/resw lookup happens,
        // and synchronize our live LocalizationService catalog with the loaded setting.
        ApplyLanguageOverride(settings.Current.Language);
        Services.GetRequiredService<LocalizationService>().SyncFromSettings();

        var cloud = Services.GetRequiredService<ICloudService>();
        if (cloud is CloudService concreteCloud)
            await concreteCloud.RestoreSessionAsync();

        var notifications = Services.GetRequiredService<Services.NotificationService>();
        notifications.Initialize();

        var mainWindow = new MainWindow();
        _window = mainWindow;
        MainWindow = mainWindow;
        mainWindow.Activate();

        WireAdvancedSecurityGuards(settings, notifications);

        // Handle Windows Explorer Right-Click ("Scan with BECETTI YARA") launch argument
        var yaraScanArg = ExtractYaraScanArgument(Environment.GetCommandLineArgs());
        if (!string.IsNullOrWhiteSpace(yaraScanArg))
            mainWindow.NavigateTo("Yara", "AUTO:" + yaraScanArg);
    }

    private static void WireAdvancedSecurityGuards(ISettingsService settings, Services.NotificationService notifications)
    {
        var folderGuard = Services.GetRequiredService<IRealTimeYaraGuardService>();
        folderGuard.AutoQuarantineEnabled = settings.Current.RealTimeYaraAutoQuarantine;
        folderGuard.ThreatDetected += (_, ev) =>
            _ = notifications.NotifyCriticalAsync("BECETTI YARA Folder Guard Alert", ev.DisplayLine);

        var canary = Services.GetRequiredService<IRansomwareCanaryService>();
        canary.CanaryTripped += (_, alert) =>
            _ = notifications.NotifyCriticalAsync("Ransomware Canary Alert!", $"{alert.ChangeType}: {alert.Details}");

        var clipboardGuard = Services.GetRequiredService<IClipboardGuardService>();
        clipboardGuard.IsEnabled = settings.Current.ClipboardGuardEnabled;
        clipboardGuard.HijackDetected += (_, alert) =>
            _ = notifications.NotifyCriticalAsync("Clipboard Hijack Detected!", alert.Message);

        var usbAutoScan = Services.GetRequiredService<IUsbAutoScanService>();
        usbAutoScan.UsbThreatDetected += (_, ev) =>
            _ = notifications.NotifyCriticalAsync("USB YARA Threat Detected!", ev.Summary);

        var hostsGuard = Services.GetRequiredService<IHostsDnsGuardService>();
        hostsGuard.HostsTampered += (_, alert) =>
            _ = notifications.NotifyCriticalAsync("Hosts File Modified!", alert.Message);

        var fim = Services.GetRequiredService<IFileIntegrityMonitorService>();
        fim.IntegrityViolation += (_, alert) =>
            _ = notifications.NotifyCriticalAsync("File Integrity Alert (FIM)!", $"{alert.ChangeType}: {alert.FilePath}");

        // Subscribe to real Windows Clipboard changes on the UI thread
        try
        {
            Windows.ApplicationModel.DataTransfer.Clipboard.ContentChanged += async (_, _) =>
            {
                if (!clipboardGuard.IsEnabled)
                    return;
                try
                {
                    var pkg = Windows.ApplicationModel.DataTransfer.Clipboard.GetContent();
                    if (pkg.Contains(Windows.ApplicationModel.DataTransfer.StandardDataFormats.Text))
                    {
                        var text = await pkg.GetTextAsync();
                        clipboardGuard.ObserveClipboardText(text);
                    }
                }
                catch
                {
                    // Ignore transient clipboard lock from other apps
                }
            };
        }
        catch
        {
            // Clipboard API unavailable in restricted contexts
        }

        // Start user-enabled persistent background guards cleanly in the background
        _ = Task.Run(async () =>
        {
            try
            {
                if (settings.Current.RealTimeYaraGuardEnabled)
                    await folderGuard.StartAsync();

                if (settings.Current.RansomwareCanaryEnabled)
                    await canary.ArmAsync();

                if (settings.Current.UsbAutoScanEnabled)
                    usbAutoScan.Start();

                if (settings.Current.HostsGuardEnabled)
                    hostsGuard.StartWatching();

                if (settings.Current.FimAutoWatchEnabled)
                    await fim.StartWatchingAsync();

                var scheduledYara = Services.GetRequiredService<IScheduledYaraUpdateService>();
                await scheduledYara.LoadConfigAsync();
                if (scheduledYara.CurrentConfig.Enabled)
                    scheduledYara.StartBackgroundLoop();

                var scanScheduler = Services.GetRequiredService<IScanSchedulerService>();
                scanScheduler.ScanCompleted += (_, res) =>
                {
                    if (res.YaraThreatsFound > 0)
                        _ = notifications.NotifyCriticalAsync("Scheduled YARA Audit Alert!", res.Summary);
                };
                if (settings.Current.ScheduledScanEnabled)
                    scanScheduler.Start();
            }
            catch
            {
                // Non-fatal startup guard error
            }
        });
    }

    private static string? ExtractYaraScanArgument(string[] args)
    {
        for (int i = 0; i < args.Length - 1; i++)
        {
            if (string.Equals(args[i], "--yara-scan", StringComparison.OrdinalIgnoreCase) &&
                !string.IsNullOrWhiteSpace(args[i + 1]))
            {
                return args[i + 1].Trim('"');
            }
        }
        return null;
    }

    /// <summary>
    /// Sets the resource language override used by Windows/WinUI3 resource loaders.
    /// Live UI updates are handled immediately by LocalizationService + helpers:Loc.Uid.
    /// </summary>
    public static void ApplyLanguageOverride(string languageCode)
    {
        var bcp47 = languageCode switch
        {
            "ar" or "ar-SA" => "ar-SA",
            "fr" or "fr-FR" => "fr-FR",
            "es" or "es-ES" => "es-ES",
            "de" or "de-DE" => "de-DE",
            "tr" or "tr-TR" => "tr-TR",
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
