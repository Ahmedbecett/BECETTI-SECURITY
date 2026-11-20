using Becetti.Security.App.Views;
using Becetti.Security.Core.Services;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace Becetti.Security.App;

/// <summary>Main window: navigation shell hosting the ten product pages.</summary>
public sealed partial class MainWindow : Window
{
    private readonly Dictionary<string, Type> _pages = new()
    {
        ["Dashboard"] = typeof(DashboardPage),
        ["Scan"] = typeof(ScanPage),
        ["Protection"] = typeof(ProtectionPage),
        ["Cloud"] = typeof(CloudPage),
        ["Threats"] = typeof(ThreatsPage),
        ["Privacy"] = typeof(PrivacyPage),
        ["History"] = typeof(HistoryPage),
        ["Updates"] = typeof(UpdatesPage),
        ["Settings"] = typeof(SettingsPage),
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
            ContentFrame.Navigate(pageType);
        }
    }
}
