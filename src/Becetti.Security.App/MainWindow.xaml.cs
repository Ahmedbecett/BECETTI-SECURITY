using Becetti.Security.App.Helpers;
using Becetti.Security.App.Views;
using Becetti.Security.Core.Services;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Windows.UI;

namespace Becetti.Security.App;

/// <summary>Main window: navigation shell hosting the product pages with instant live localization.</summary>
public sealed partial class MainWindow : Window
{
    private readonly LocalizationService _localization;
    private ProtectionLevel _lastProtectionLevel = ProtectionLevel.Unknown;
    private string? _lastYaraVersion;
    private int _lastYaraRuleCount;

    private readonly Dictionary<string, Type> _pages = new()
    {
        ["Dashboard"] = typeof(DashboardPage),
        ["Scan"] = typeof(ScanPage),
        ["Yara"] = typeof(YaraScannerPage),
        ["AdvancedDefense"] = typeof(AdvancedDefensePage),
        ["Protection"] = typeof(ProtectionPage),
        ["Cloud"] = typeof(CloudPage),
        ["Ai"] = typeof(BecettiAiPage),
        ["Ransomware"] = typeof(RansomwarePage),
        ["Threats"] = typeof(ThreatsPage),
        ["PcHealth"] = typeof(PcHealthPage),
        ["Startup"] = typeof(StartupManagerPage),
        ["Software"] = typeof(SoftwareManagerPage),
        ["Drivers"] = typeof(DriverMonitorPage),
        ["Usb"] = typeof(UsbProtectionPage),
        ["Network"] = typeof(NetworkMonitorPage),
        ["Vulnerability"] = typeof(VulnerabilityAdvisorPage),
        ["Browser"] = typeof(BrowserSecurityPage),
        ["Identity"] = typeof(IdentityProtectionPage),
        ["Wifi"] = typeof(WifiSecurityPage),
        ["ScheduledScan"] = typeof(ScheduledScanPage),
        ["Backup"] = typeof(BackupAdvisorPage),
        ["Reports"] = typeof(SecurityReportsPage),
        ["CloudSync"] = typeof(CloudSyncPage),
        ["Knowledge"] = typeof(KnowledgeBasePage),
        ["ThreatIntel"] = typeof(ThreatIntelligencePage),
        ["DataBreach"] = typeof(DataBreachPage),
        ["IpReputation"] = typeof(IpReputationPage),
        ["SecureVault"] = typeof(SecureVaultPage),
        ["FileShredder"] = typeof(FileShredderPage),
        ["ParentalControl"] = typeof(ParentalControlPage),
        ["GameMode"] = typeof(GamePerformanceModePage),
        ["Emergency"] = typeof(EmergencyCenterPage),
        ["Privacy"] = typeof(PrivacyPage),
        ["History"] = typeof(HistoryPage),
        ["Updates"] = typeof(UpdatesPage),
        ["Settings"] = typeof(SettingsPage),
        ["Contact"] = typeof(ContactPage),
        ["About"] = typeof(AboutPage)
    };

    public MainWindow()
    {
        InitializeComponent();
        ConfigureTitleBar();
        NavView.ItemInvoked += OnNavigationInvoked;

        _localization = App.Services.GetRequiredService<LocalizationService>();
        ApplyShellLocalization();
        _localization.LanguageChanged += (_, _) =>
        {
            DispatcherQueue.TryEnqueue(ApplyShellLocalization);
        };

        ContentFrame.Navigate(typeof(DashboardPage));

        _ = LoadFooterStatusAsync();
    }

    private void ConfigureTitleBar()
    {
        try
        {
            if (!AppWindowTitleBar.IsCustomizationSupported())
                return;

            var titleBar = AppWindow.TitleBar;
            titleBar.BackgroundColor = Color.FromArgb(0xFF, 0x0D, 0x11, 0x19);
            titleBar.InactiveBackgroundColor = Color.FromArgb(0xFF, 0x09, 0x0C, 0x12);
            titleBar.ForegroundColor = Color.FromArgb(0xFF, 0xF1, 0xF5, 0xF9);
            titleBar.InactiveForegroundColor = Color.FromArgb(0xFF, 0x64, 0x74, 0x8B);

            titleBar.ButtonBackgroundColor = Color.FromArgb(0xFF, 0x0D, 0x11, 0x19);
            titleBar.ButtonForegroundColor = Color.FromArgb(0xFF, 0x94, 0xA3, 0xB8);
            titleBar.ButtonHoverBackgroundColor = Color.FromArgb(0xFF, 0x17, 0x20, 0x30);
            titleBar.ButtonHoverForegroundColor = Color.FromArgb(0xFF, 0xF1, 0xF5, 0xF9);
            titleBar.ButtonPressedBackgroundColor = Color.FromArgb(0xFF, 0x1E, 0x2B, 0x40);
            titleBar.ButtonPressedForegroundColor = Color.FromArgb(0xFF, 0xFF, 0xFF, 0xFF);
            titleBar.ButtonInactiveBackgroundColor = Color.FromArgb(0xFF, 0x09, 0x0C, 0x12);
            titleBar.ButtonInactiveForegroundColor = Color.FromArgb(0xFF, 0x64, 0x74, 0x8B);
        }
        catch
        {
            // Keep default Windows title bar if host environment does not support customization.
        }
    }

    private void ApplyShellLocalization()
    {
        if (Content is FrameworkElement root)
            root.FlowDirection = _localization.IsRtl ? FlowDirection.RightToLeft : FlowDirection.LeftToRight;

        // Immediately refresh every NavigationViewItem label (including off-screen items)
        foreach (var item in NavView.MenuItems.OfType<NavigationViewItem>())
        {
            var uid = Loc.GetUid(item);
            if (!string.IsNullOrWhiteSpace(uid))
                Loc.Apply(item, uid);
        }

        ToolTipService.SetToolTip(HelpButton, _localization.Get("HeaderHelpToolTip", "Help"));
        ToolTipService.SetToolTip(AboutButton, _localization.Get("NavAbout.Content", "About"));
        ToolTipService.SetToolTip(SettingsButton, _localization.Get("NavSettings.Content", "Settings"));

        RenderFooterStatus();
    }

    private void OnNavigationInvoked(NavigationView sender, NavigationViewItemInvokedEventArgs args)
    {
        if (args.InvokedItemContainer?.Tag is string tag && _pages.TryGetValue(tag, out var pageType))
        {
            ContentFrame.Navigate(pageType, null, new Microsoft.UI.Xaml.Media.Animation.EntranceNavigationTransitionInfo());
        }
    }

    private void AiLauncherButton_Click(object sender, RoutedEventArgs e) => NavigateTo("Ai");

    private void SettingsButton_Click(object sender, RoutedEventArgs e) => NavigateTo("Settings");

    private void AboutButton_Click(object sender, RoutedEventArgs e) => NavigateTo("About");

    private async void HelpButton_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new ContentDialog
        {
            Title = _localization.Get("HelpDialogTitle", "BECETTI SECURITY — Help"),
            CloseButtonText = _localization.Get("CloseButton", "Close"),
            XamlRoot = (Content as FrameworkElement)?.XamlRoot,
            Content = new TextBlock
            {
                TextWrapping = TextWrapping.Wrap,
                Text = _localization.Get(
                    "HelpDialogBody",
                    "BECETTI SECURITY combines the official local Native YARA Engine (VirusTotal/yara x64) with Microsoft Defender:\n\n" +
                    "• YARA Engine runs real compiled .yar / .yara rules locally on your files and folders, validates every rule with yarac64 before loading, isolates invalid rules, and supports trusted rule repository updates.\n" +
                    "• Smart Scan lets you run both Native YARA local scans and real Microsoft Defender scans (MpCmdRun.exe).\n" +
                    "• Real-Time Protection, Updates, and Threat Management read and manage Microsoft Defender through supported Windows interfaces.\n" +
                    "• BECETTI AI explains real scan reports and guides you inside the app.\n\n" +
                    "BECETTI SECURITY never simulates or fabricates detections.")
            }
        };

        await dialog.ShowAsync();
    }

    private void NavigateTo(string tag) => NavigateTo(tag, null);

    public void NavigateTo(string tag, object? parameter)
    {
        if (_pages.TryGetValue(tag, out var pageType))
        {
            ContentFrame.Navigate(pageType, parameter);
            foreach (var item in NavView.MenuItems.OfType<NavigationViewItem>())
            {
                if (item.Tag as string == tag)
                {
                    NavView.SelectedItem = item;
                    break;
                }
            }
        }
    }

    /// <summary>
    /// Reads real Native YARA Engine + Microsoft Defender state once at startup to populate
    /// the footer status bar. Never fabricated.
    /// </summary>
    private async Task LoadFooterStatusAsync()
    {
        try
        {
            var yara = App.Services.GetRequiredService<IYaraEngineService>();
            var yaraInit = await yara.InitializeAsync();
            if (yaraInit.Success && yaraInit.Value is not null && yaraInit.Value.IsAvailable)
            {
                _lastYaraVersion = yaraInit.Value.Version;
                _lastYaraRuleCount = yaraInit.Value.ActiveRuleCount;
            }
        }
        catch
        {
            // Keep YARA status unknown if initialization fails
        }

        try
        {
            var defender = App.Services.GetRequiredService<IDefenderService>();
            var result = await defender.GetStatusAsync();
            _lastProtectionLevel = ProtectionStatusEvaluator.Evaluate(result.Success ? result.Value : null);
        }
        catch
        {
            _lastProtectionLevel = ProtectionLevel.Unknown;
        }

        DispatcherQueue.TryEnqueue(RenderFooterStatus);
    }

    private void RenderFooterStatus()
    {
        var yaraSuffix = !string.IsNullOrWhiteSpace(_lastYaraVersion)
            ? $" · YARA {_lastYaraVersion} ({_lastYaraRuleCount})"
            : string.Empty;

        var (key, fallback, brushKey) = _lastProtectionLevel switch
        {
            ProtectionLevel.Protected => ("FooterProtected", "Protected — Microsoft Defender active", "AccentGreenBrush"),
            ProtectionLevel.Warning => ("FooterWarning", "Needs attention — see Real-Time Protection", "WarningBrush"),
            ProtectionLevel.Danger => ("FooterDanger", "At risk — Defender antivirus is disabled", "DangerBrush"),
            _ => !string.IsNullOrWhiteSpace(_lastYaraVersion)
                ? ("FooterYaraReady", "Native YARA Engine ready", "ElectricBlueBrush")
                : ("FooterUnknown", "Protection status unknown — could not verify", "TextSecondaryBrush")
        };

        FooterReadinessText.Text = _localization.Get(key, fallback) + yaraSuffix;
        if (Application.Current.Resources.TryGetValue(brushKey, out var brush) && brush is Brush b)
        {
            FooterReadinessText.Foreground = b;
            ReadinessDot.Fill = b;
        }
    }
}
