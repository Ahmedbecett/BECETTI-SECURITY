using Becetti.Security.App.Views;
using Becetti.Security.Core.Services;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;

namespace Becetti.Security.App;

/// <summary>Main window: navigation shell hosting the product pages.</summary>
public sealed partial class MainWindow : Window
{
    private readonly Dictionary<string, Type> _pages = new()
    {
        ["Dashboard"] = typeof(DashboardPage),
        ["Scan"] = typeof(ScanPage),
        ["Protection"] = typeof(ProtectionPage),
        ["Cloud"] = typeof(CloudPage),
        ["Ai"] = typeof(BecettiAiPage),
        ["Ransomware"] = typeof(RansomwarePage),
        ["Threats"] = typeof(ThreatsPage),
        ["PcHealth"] = typeof(PcHealthPage),
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
        NavView.ItemInvoked += OnNavigationInvoked;

        var localization = App.Services.GetRequiredService<LocalizationService>();
        ApplyFlowDirection(localization);
        localization.LanguageChanged += (_, _) => ApplyFlowDirection(localization);

        ContentFrame.Navigate(typeof(DashboardPage));

        _ = LoadFooterStatusAsync();
    }

    private void ApplyFlowDirection(LocalizationService localization)
    {
        // Window.Content is typed as UIElement; FlowDirection lives on FrameworkElement
        // (the root Grid set by InitializeComponent), so it must be cast first.
        if (Content is FrameworkElement root)
            root.FlowDirection = localization.IsRtl ? FlowDirection.RightToLeft : FlowDirection.LeftToRight;
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
            Title = "BECETTI SECURITY — Help",
            CloseButtonText = "Close",
            XamlRoot = (Content as FrameworkElement)?.XamlRoot,
            Content = new TextBlock
            {
                TextWrapping = TextWrapping.Wrap,
                Text =
                    "BECETTI SECURITY reads and manages Microsoft Defender through supported Windows " +
                    "interfaces only — it does not run its own antivirus engine.\n\n" +
                    "• Smart Scan runs a real Defender scan (MpCmdRun.exe) and shows Defender's own result.\n" +
                    "• Real-Time Protection shows Defender's verified live state and lets you toggle it " +
                    "(elevation required); changes are re-checked before success is reported.\n" +
                    "• Updates pulls security intelligence only from Microsoft's own update service.\n" +
                    "• Threat Management lists real Defender detections and removes them through Defender, " +
                    "then re-checks the result.\n\n" +
                    "If a page shows \"Unknown\", BECETTI SECURITY could not verify that value — it never " +
                    "guesses or invents a status."
            }
        };

        await dialog.ShowAsync();
    }

    private void NavigateTo(string tag)
    {
        if (_pages.TryGetValue(tag, out var pageType))
        {
            ContentFrame.Navigate(pageType);
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
    /// Reads real Defender state once at startup to populate the footer status bar.
    /// Never fabricated: unreachable Defender shows "Unknown", not "Protected".
    /// </summary>
    private async Task LoadFooterStatusAsync()
    {
        try
        {
            var defender = App.Services.GetRequiredService<IDefenderService>();
            var result = await defender.GetStatusAsync();
            var level = ProtectionStatusEvaluator.Evaluate(result.Success ? result.Value : null);

            var (text, brushKey) = level switch
            {
                ProtectionLevel.Protected => ("Protected — Microsoft Defender is active and verified", "AccentGreenBrush"),
                ProtectionLevel.Warning => ("Needs attention — see Real-Time Protection", "WarningBrush"),
                ProtectionLevel.Danger => ("At risk — Antivirus is disabled", "DangerBrush"),
                _ => ("Defender status unknown — could not verify", "TextSecondaryBrush")
            };

            FooterReadinessText.Text = text;
            if (Application.Current.Resources.TryGetValue(brushKey, out var brush) && brush is Microsoft.UI.Xaml.Media.Brush b)
            {
                FooterReadinessText.Foreground = b;
                ReadinessDot.Fill = b;
            }
        }
        catch
        {
            FooterReadinessText.Text = "Defender status unknown — could not verify";
        }
    }
}
