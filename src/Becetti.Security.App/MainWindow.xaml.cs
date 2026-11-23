using System.Collections.ObjectModel;
using Becetti.Security.App.Helpers;
using Becetti.Security.App.Services;
using Becetti.Security.App.Views;
using Becetti.Security.Core.Services;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Windows.System;
using Windows.UI;

namespace Becetti.Security.App;

public sealed class CommandPaletteItem
{
    public string Title { get; init; } = string.Empty;
    public string Subtitle { get; init; } = string.Empty;
    public string Category { get; init; } = "Navigate";
    public string TargetTag { get; init; } = string.Empty;
    public object? Parameter { get; init; }
}

/// <summary>
/// Main window: enterprise grouped navigation shell, Ctrl+K Command Palette,
/// custom Obsidian Windows TitleBar, System Tray minimize-to-tray host, and live localization.
/// </summary>
public sealed partial class MainWindow : Window
{
    private readonly LocalizationService _localization;
    private readonly ISettingsService _settings;
    private readonly SystemTrayService _tray;
    private readonly IAppLockService _appLock;
    private readonly IAiTriageNavigator _aiTriage;
    private static readonly HashSet<string> ProtectedTags = new(StringComparer.OrdinalIgnoreCase)
    {
        "Settings", "Emergency", "AdvancedDefense"
    };
    private bool _allowFullExit;
    private ProtectionLevel _lastProtectionLevel = ProtectionLevel.Unknown;
    private string? _lastYaraVersion;
    private int _lastYaraRuleCount;

    private readonly List<CommandPaletteItem> _allPaletteItems = new();
    private readonly ObservableCollection<CommandPaletteItem> _filteredPaletteItems = new();

    private readonly Dictionary<string, Type> _pages = new()
    {
        ["Dashboard"] = typeof(DashboardPage),
        ["Scan"] = typeof(ScanPage),
        ["Yara"] = typeof(YaraScannerPage),
        ["AdvancedDefense"] = typeof(AdvancedDefensePage),
        ["EdrCenter"] = typeof(EdrCenterPage),
        ["ProactiveDefense"] = typeof(ProactiveDefensePage),
        ["GlobalIntel"] = typeof(GlobalIntelPage),
        ["SocOperations"] = typeof(SocOperationsPage),
        ["InfraCompliance"] = typeof(InfrastructureCompliancePage),
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
        _settings = App.Services.GetRequiredService<ISettingsService>();
        _tray = App.Services.GetRequiredService<SystemTrayService>();
        _appLock = App.Services.GetRequiredService<IAppLockService>();
        _aiTriage = App.Services.GetRequiredService<IAiTriageNavigator>();
        _aiTriage.TriageRequested += (_, prompt) =>
            DispatcherQueue.TryEnqueue(() => NavigateTo("Ai", prompt));

        CommandPaletteList.ItemsSource = _filteredPaletteItems;
        ConfigureSystemTray();

        ApplyShellLocalization();
        _localization.LanguageChanged += (_, _) =>
        {
            DispatcherQueue.TryEnqueue(ApplyShellLocalization);
        };

        ContentFrame.Navigate(typeof(DashboardPage));
        _ = LoadFooterStatusAsync();

        if (!_settings.Current.OnboardingCompleted)
        {
            ShowOnboardingWizard();
        }
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
        catch { }
    }

    private void ConfigureSystemTray()
    {
        try
        {
            _tray.Initialize("BECETTI SECURITY — Active Protection");
            _tray.OpenRequested += () => DispatcherQueue.TryEnqueue(RestoreFromTray);
            _tray.NavigateRequested += tag => DispatcherQueue.TryEnqueue(() =>
            {
                RestoreFromTray();
                NavigateTo(tag, null);
            });
            _tray.ExitRequested += () => DispatcherQueue.TryEnqueue(ExitApplicationCompletely);

            AppWindow.Closing += OnAppWindowClosing;
        }
        catch { }
    }

    private void OnAppWindowClosing(AppWindow sender, AppWindowClosingEventArgs args)
    {
        if (!_allowFullExit && _settings.Current.MinimizeToTrayOnClose)
        {
            args.Cancel = true;
            try { sender.Hide(); } catch { }
        }
        else
        {
            _tray.Dispose();
        }
    }

    public void RestoreFromTray()
    {
        try
        {
            AppWindow.Show();
            Activate();
        }
        catch { }
    }

    public void ExitApplicationCompletely()
    {
        _allowFullExit = true;
        _tray.Dispose();
        Close();
    }

    private void ApplyShellLocalization()
    {
        if (Content is FrameworkElement root)
            root.FlowDirection = _localization.IsRtl ? FlowDirection.RightToLeft : FlowDirection.LeftToRight;

        LocalizeNavItems(NavView.MenuItems);

        ToolTipService.SetToolTip(HelpButton, _localization.Get("HeaderHelpToolTip", "Help"));
        ToolTipService.SetToolTip(AboutButton, _localization.Get("NavAbout.Content", "About"));
        ToolTipService.SetToolTip(SettingsButton, _localization.Get("NavSettings.Content", "Settings"));

        RebuildCommandPaletteIndex();
        RenderFooterStatus();
    }

    private static void LocalizeNavItems(IList<object> items)
    {
        foreach (var item in items.OfType<NavigationViewItem>())
        {
            var uid = Loc.GetUid(item);
            if (!string.IsNullOrWhiteSpace(uid))
                Loc.Apply(item, uid);

            if (item.MenuItems.Count > 0)
                LocalizeNavItems(item.MenuItems);
        }
    }

    private void RebuildCommandPaletteIndex()
    {
        _allPaletteItems.Clear();

        // Quick High-Value Security Actions
        _allPaletteItems.Add(new CommandPaletteItem
        {
            Title = "Run Native YARA Scan",
            Subtitle = "Open YARA v4.6.0 Engine to scan files, folders, or generate AI rules",
            Category = "Action",
            TargetTag = "Yara"
        });
        _allPaletteItems.Add(new CommandPaletteItem
        {
            Title = "Audit Windows Hardening & Persistence (EDR)",
            Subtitle = "Check Secure Boot, HVCI, BitLocker, SMBv1, Autoruns, Hosts/DNS & Camera/Mic",
            Category = "Action",
            TargetTag = "EdrCenter"
        });
        _allPaletteItems.Add(new CommandPaletteItem
        {
            Title = "Live Process Memory Scan & AES-256 Quarantine",
            Subtitle = "Scan live RAM processes with YARA, inspect PE/Entropy, manage Quarantine",
            Category = "Action",
            TargetTag = "AdvancedDefense"
        });
        _allPaletteItems.Add(new CommandPaletteItem
        {
            Title = "Emergency Network Kill-Switch & Forensic ZIP",
            Subtitle = "Isolate host firewall immediately or export incident evidence bundle",
            Category = "Emergency",
            TargetTag = "Emergency"
        });
        _allPaletteItems.Add(new CommandPaletteItem
        {
            Title = "Proactive Defense: Browser Extensions, Winget, Wi-Fi/ARP & DLL Inspector",
            Subtitle = "Audit extensions, patch outdated apps, detect ARP spoofing, inspect unsigned DLLs & shred files",
            Category = "Action",
            TargetTag = "ProactiveDefense"
        });
        _allPaletteItems.Add(new CommandPaletteItem
        {
            Title = "Generate Executive Security Report (HTML / Print-to-PDF)",
            Subtitle = "Export full localized security score, hardening table & recent events report",
            Category = "Reports",
            TargetTag = "ProactiveDefense"
        });
        _allPaletteItems.Add(new CommandPaletteItem
        {
            Title = "Global Intel: Threat Feeds (abuse.ch), GeoIP Radar & MITRE ATT&CK",
            Subtitle = "Live C2 IP feeds, outbound country/ASN radar, 1-click firewall blocker, privacy hardener & updater",
            Category = "Global",
            TargetTag = "GlobalIntel"
        });
        _allPaletteItems.Add(new CommandPaletteItem
        {
            Title = "SOC Operations: Local SIEM, Sigma Rules, Process Tree, SOAR, EML Forensics & Root CA",
            Subtitle = "Correlate Windows Event Logs, run Sigma YAML rules, hunt parent-child anomalies & run SOAR containment",
            Category = "SOC",
            TargetTag = "SocOperations"
        });
        _allPaletteItems.Add(new CommandPaletteItem
        {
            Title = "Infrastructure & Compliance: LAN/Ports, DNS Logger, Privacy Cleaner, Vault Pro, Cloud Fleet & CIS/NIST",
            Subtitle = "Discover LAN ARP devices, audit DNS cache vs URLhaus, AES-256-GCM Vault Pro & export CIS/NIST reports",
            Category = "Compliance",
            TargetTag = "InfraCompliance"
        });
        _allPaletteItems.Add(new CommandPaletteItem
        {
            Title = "Launch First-Run Setup Wizard (6 Languages & Recommended Shields)",
            Subtitle = "Re-open the 3-step interactive BECETTI SECURITY onboarding wizard",
            Category = "Setup",
            TargetTag = "__Onboarding__"
        });
        _allPaletteItems.Add(new CommandPaletteItem
        {
            Title = "Ask BECETTI AI Security Assistant",
            Subtitle = "Investigate alerts, decode scripts, or explain system status",
            Category = "AI",
            TargetTag = "Ai"
        });

        // Index every leaf navigation page automatically
        CollectNavPaletteItems(NavView.MenuItems, "Navigate");
        FilterCommandPalette(CommandPaletteInput?.Text ?? string.Empty);
    }

    private void CollectNavPaletteItems(IList<object> items, string groupLabel)
    {
        foreach (var item in items.OfType<NavigationViewItem>())
        {
            var label = item.Content?.ToString() ?? string.Empty;
            if (item.MenuItems.Count > 0)
            {
                CollectNavPaletteItems(item.MenuItems, string.IsNullOrWhiteSpace(label) ? groupLabel : label);
            }
            else if (item.Tag is string tag && !string.IsNullOrWhiteSpace(label))
            {
                _allPaletteItems.Add(new CommandPaletteItem
                {
                    Title = label,
                    Subtitle = $"Open {label}",
                    Category = groupLabel,
                    TargetTag = tag
                });
            }
        }
    }

    public void OpenCommandPalette()
    {
        CommandPaletteOverlay.Visibility = Visibility.Visible;
        CommandPaletteInput.Text = string.Empty;
        FilterCommandPalette(string.Empty);
        CommandPaletteInput.Focus(FocusState.Programmatic);
    }

    public void CloseCommandPalette()
    {
        CommandPaletteOverlay.Visibility = Visibility.Collapsed;
    }

    private void FilterCommandPalette(string query)
    {
        _filteredPaletteItems.Clear();
        var q = query.Trim();

        IEnumerable<CommandPaletteItem> matches = string.IsNullOrWhiteSpace(q)
            ? _allPaletteItems
            : _allPaletteItems.Where(i =>
                i.Title.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                i.Subtitle.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                i.Category.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                i.TargetTag.Contains(q, StringComparison.OrdinalIgnoreCase));

        foreach (var m in matches.Take(18))
            _filteredPaletteItems.Add(m);

        if (_filteredPaletteItems.Count > 0 && CommandPaletteList is not null)
            CommandPaletteList.SelectedIndex = 0;
    }

    private void ExecutePaletteItem(CommandPaletteItem? item)
    {
        if (item is null) return;
        CloseCommandPalette();
        if (string.Equals(item.TargetTag, "__Onboarding__", StringComparison.Ordinal))
        {
            ShowOnboardingWizard();
            return;
        }
        NavigateTo(item.TargetTag, item.Parameter);
    }

    private void CommandPaletteAccelerator_Invoked(KeyboardAccelerator sender, KeyboardAcceleratorInvokedEventArgs args)
    {
        args.Handled = true;
        if (CommandPaletteOverlay.Visibility == Visibility.Visible)
            CloseCommandPalette();
        else
            OpenCommandPalette();
    }

    private void EscapeAccelerator_Invoked(KeyboardAccelerator sender, KeyboardAcceleratorInvokedEventArgs args)
    {
        if (CommandPaletteOverlay.Visibility == Visibility.Visible)
        {
            args.Handled = true;
            CloseCommandPalette();
        }
    }

    private void CommandPaletteButton_Click(object sender, RoutedEventArgs e) => OpenCommandPalette();
    private void CloseCommandPalette_Click(object sender, RoutedEventArgs e) => CloseCommandPalette();
    private void CommandPaletteBackdrop_PointerPressed(object sender, PointerRoutedEventArgs e) => CloseCommandPalette();
    private void CommandPaletteCard_PointerPressed(object sender, PointerRoutedEventArgs e) => e.Handled = true;

    private void CommandPaletteInput_TextChanged(object sender, TextChangedEventArgs e) =>
        FilterCommandPalette(CommandPaletteInput.Text);

    private void CommandPaletteInput_KeyDown(object sender, KeyRoutedEventArgs e)
    {
        if (e.Key == VirtualKey.Enter)
        {
            e.Handled = true;
            ExecutePaletteItem(CommandPaletteList.SelectedItem as CommandPaletteItem ?? _filteredPaletteItems.FirstOrDefault());
        }
        else if (e.Key == VirtualKey.Down && _filteredPaletteItems.Count > 0)
        {
            e.Handled = true;
            CommandPaletteList.SelectedIndex = Math.Min(CommandPaletteList.SelectedIndex + 1, _filteredPaletteItems.Count - 1);
            CommandPaletteList.ScrollIntoView(CommandPaletteList.SelectedItem);
        }
        else if (e.Key == VirtualKey.Up && _filteredPaletteItems.Count > 0)
        {
            e.Handled = true;
            CommandPaletteList.SelectedIndex = Math.Max(CommandPaletteList.SelectedIndex - 1, 0);
            CommandPaletteList.ScrollIntoView(CommandPaletteList.SelectedItem);
        }
        else if (e.Key == VirtualKey.Escape)
        {
            e.Handled = true;
            CloseCommandPalette();
        }
    }

    private void CommandPaletteList_ItemClick(object sender, ItemClickEventArgs e) =>
        ExecutePaletteItem(e.ClickedItem as CommandPaletteItem);

    private void OnNavigationInvoked(NavigationView sender, NavigationViewItemInvokedEventArgs args)
    {
        if (args.InvokedItemContainer?.Tag is string tag)
            NavigateTo(tag, null);
    }

    private void AiLauncherButton_Click(object sender, RoutedEventArgs e) => NavigateTo("Ai");
    private void SettingsButton_Click(object sender, RoutedEventArgs e) => NavigateTo("Settings");
    private void AboutButton_Click(object sender, RoutedEventArgs e) => NavigateTo("About");

    private async void HelpButton_Click(object sender, RoutedEventArgs e)
    {
        try
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
                        "BECETTI SECURITY combines the official local Native YARA Engine (VirusTotal/yara x64), EDR & Windows Hardening tools, Global Threat Intel & GeoIP Radar, and Microsoft Defender:\n\n" +
                        "• Press Ctrl+K anytime to open the instant Command Palette.\n" +
                        "• YARA Engine runs real compiled .yar/.yara rules locally, validates every rule with yarac64, and includes AI YARA Rule Studio.\n" +
                        "• Global Intel & Radar provides live abuse.ch C2/Malware feeds, outbound GeoIP Radar with 1-click Firewall blocking, MITRE ATT&CK matrix, Privacy Hardener, and GitHub Releases Auto-Updater.\n" +
                        "• EDR & Hardening provides Deep Persistence Hunter, Hosts/DNS Hijack Guard, Camera/Mic Privacy Auditor, PowerShell/LOLBins Decoder, URL Phishing Inspector, SHA-256 FIM, Windows Hardening Auditor, and Forensic ZIP Bundle export.\n\n" +
                        "BECETTI SECURITY never simulates or fabricates detections.")
                }
            };

            await dialog.ShowAsync();
        }
        catch { }
    }

    private void NavigateTo(string tag) => NavigateTo(tag, null);

    public void NavigateTo(string tag, object? parameter)
    {
        _ = NavigateToWithGateAsync(tag, parameter);
    }

    private async Task NavigateToWithGateAsync(string tag, object? parameter)
    {
        if (!_pages.TryGetValue(tag, out var pageType))
            return;

        if (ProtectedTags.Contains(tag) && _appLock.IsEnabled && !_appLock.IsSessionUnlocked)
        {
            var xamlRoot = (Content as FrameworkElement)?.XamlRoot;
            var ok = await WindowsHelloAuthHelper.VerifyAccessAsync(
                xamlRoot,
                _appLock,
                $"Verify identity to access protected BECETTI SECURITY module ({tag}).");
            if (!ok)
                return;
        }

        ContentFrame.Navigate(pageType, parameter);
        TrySelectNavItem(NavView.MenuItems, tag);
    }

    private bool TrySelectNavItem(IList<object> items, string tag)
    {
        foreach (var item in items.OfType<NavigationViewItem>())
        {
            if (item.Tag as string == tag)
            {
                NavView.SelectedItem = item;
                return true;
            }
            if (item.MenuItems.Count > 0 && TrySelectNavItem(item.MenuItems, tag))
            {
                item.IsExpanded = true;
                return true;
            }
        }
        return false;
    }

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
        catch { }

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

        var label = _localization.Get(key, fallback) + yaraSuffix;
        FooterReadinessText.Text = label;
        _tray.UpdateTooltip($"BECETTI SECURITY — {label}");

        if (Application.Current.Resources.TryGetValue(brushKey, out var brush) && brush is Brush b)
        {
            FooterReadinessText.Foreground = b;
            ReadinessDot.Fill = b;
        }
    }

    // =========================================================================
    //  World-Class 3-Step First-Run Onboarding Wizard (#4)
    // =========================================================================
    private int _onboardingStep = 1;

    public void ShowOnboardingWizard()
    {
        _onboardingStep = 1;
        RenderOnboardingStep();
        OnboardingOverlay.Visibility = Visibility.Visible;
    }

    private void RenderOnboardingStep()
    {
        OnboardingStep1.Visibility = _onboardingStep == 1 ? Visibility.Visible : Visibility.Collapsed;
        OnboardingStep2.Visibility = _onboardingStep == 2 ? Visibility.Visible : Visibility.Collapsed;
        OnboardingStep3.Visibility = _onboardingStep == 3 ? Visibility.Visible : Visibility.Collapsed;
        OnboardingBackBtn.Visibility = _onboardingStep > 1 ? Visibility.Visible : Visibility.Collapsed;

        var (title, subtitle, next1, next2, next3) = _localization.Current switch
        {
            AppLanguage.Arabic => (
                "مرحباً بك في الحماية العالمية BECETTI SECURITY",
                "واجهات ويندوز حقيقية 100% · محرك YARA v4.6.0 · مصفوفة MITRE ATT&CK · بدون أي محاكاة",
                "الخطوة التالية", "تفعيل الدروع الموصى بها", "إنهاء وفتح الاستخبارات العالمية"),
            AppLanguage.French => (
                "Bienvenue dans BECETTI SECURITY Global",
                "APIs Windows 100% réelles · YARA v4.6.0 · MITRE ATT&CK EDR · Zéro simulation",
                "Étape suivante", "Activer les boucliers recommandés", "Terminer et ouvrir Intel Global"),
            AppLanguage.Spanish => (
                "Bienvenido a BECETTI SECURITY Global",
                "APIs reales de Windows 100% · YARA v4.6.0 · MITRE ATT&CK EDR · Cero simulación",
                "Siguiente paso", "Activar escudos recomendados", "Finalizar y abrir Inteligencia Global"),
            AppLanguage.German => (
                "Willkommen bei BECETTI SECURITY Global",
                "100% echte Windows-APIs · YARA v4.6.0 · MITRE ATT&CK EDR · Null Simulation",
                "Nächster Schritt", "Empfohlene Schutzschilde aktivieren", "Abschließen & Global Intel öffnen"),
            AppLanguage.Turkish => (
                "BECETTI SECURITY Küresel Korumaya Hoş Geldiniz",
                "%100 Gerçek Windows API'leri · YARA v4.6.0 · MITRE ATT&CK EDR · Sıfır Simülasyon",
                "Sonraki Adım", "Önerilen Kalkanları Etkinleştir", "Bitir ve Küresel İstihbaratı Aç"),
            _ => (
                "Welcome to Global Endpoint Protection",
                "100% Real Windows APIs · Native YARA v4.6.0 · MITRE ATT&CK EDR · Zero Simulation",
                "Next Step", "Apply Recommended Shields", "Finish & Open Global Intel")
        };

        OnboardingTitle.Text = title;
        OnboardingSubtitle.Text = subtitle;
        OnboardingNextBtn.Content = _onboardingStep switch
        {
            1 => next1,
            2 => next2,
            _ => next3
        };
    }

    private async void OnboardingLanguage_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            if (sender is not Button btn || btn.Tag is not string code) return;
            _settings.Current.Language = code;
            App.ApplyLanguageOverride(code);
            await _localization.SetLanguageAsync(LocalizationService.ParseLanguageCode(code));
            RenderOnboardingStep();
        }
        catch { }
    }

    private void OnboardingBack_Click(object sender, RoutedEventArgs e)
    {
        if (_onboardingStep > 1)
        {
            _onboardingStep--;
            RenderOnboardingStep();
        }
    }

    private async void OnboardingNext_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            if (_onboardingStep == 1)
            {
                _onboardingStep = 2;
                RenderOnboardingStep();
                return;
            }

            if (_onboardingStep == 2)
            {
                _settings.Current.RealTimeYaraGuardEnabled = ObYaraGuardCheck.IsChecked == true;
                _settings.Current.RansomwareCanaryEnabled = ObCanaryCheck.IsChecked == true;
                _settings.Current.HostsGuardEnabled = ObHostsGuardCheck.IsChecked == true;
                _settings.Current.MinimizeToTrayOnClose = ObTrayCheck.IsChecked == true;
                await _settings.SaveAsync();

                try
                {
                    if (_settings.Current.RealTimeYaraGuardEnabled)
                        await App.Services.GetRequiredService<IRealTimeYaraGuardService>().StartAsync();
                    if (_settings.Current.RansomwareCanaryEnabled)
                        await App.Services.GetRequiredService<IRansomwareCanaryService>().ArmAsync();
                    if (_settings.Current.HostsGuardEnabled)
                        App.Services.GetRequiredService<IHostsDnsGuardService>().StartWatching();
                }
                catch { }

                _onboardingStep = 3;
                RenderOnboardingStep();
                return;
            }

            _settings.Current.OnboardingCompleted = true;
            await _settings.SaveAsync();
            OnboardingOverlay.Visibility = Visibility.Collapsed;
            NavigateTo("GlobalIntel", null);
        }
        catch { }
    }

    private async void OnboardingSkip_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            _settings.Current.OnboardingCompleted = true;
            await _settings.SaveAsync();
            OnboardingOverlay.Visibility = Visibility.Collapsed;
        }
        catch { }
    }
}
