using System.ComponentModel;
using Becetti.Security.App.ViewModels;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media.Animation;
using Microsoft.UI.Xaml.Navigation;
using Windows.Storage.Pickers;
using WinRT.Interop;

namespace Becetti.Security.App.Views;

public sealed partial class ScanPage : Page
{
    private Storyboard? _mascotPulseStoryboard;

    public ScanViewModel ViewModel { get; }

    public ScanPage()
    {
        InitializeComponent();
        ViewModel = App.Services.GetRequiredService<ScanViewModel>();
        ViewModel.PropertyChanged += ViewModel_PropertyChanged;
    }

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);

        // A caller (e.g. USB Protection's "Scan this drive") can pass a real path as the
        // navigation parameter to prefill the Custom Scan target — the user still has to
        // press Start Custom Scan themselves, nothing is triggered automatically here.
        if (e.Parameter is string targetPath && !string.IsNullOrWhiteSpace(targetPath))
            ViewModel.TargetPath = targetPath;
    }

    private void ViewModel_PropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName != nameof(ScanViewModel.MascotMood))
            return;

        if (ViewModel.MascotMood == ScanMascotMood.Scanning)
            StartMascotPulse();
        else
            StopMascotPulse();
    }

    /// <summary>
    /// Pulsing glow behind the robot mascot, only while a real Defender scan
    /// (ViewModel.IsScanning) is actually in progress - this mirrors
    /// DashboardPage's float animation pattern, but is tied to real activity
    /// instead of being purely decorative.
    /// </summary>
    private void StartMascotPulse()
    {
        if (_mascotPulseStoryboard is not null)
            return;

        var animation = new DoubleAnimation
        {
            From = 0.3,
            To = 0.65,
            Duration = new Duration(TimeSpan.FromSeconds(0.9)),
            AutoReverse = true,
            RepeatBehavior = RepeatBehavior.Forever,
            EasingFunction = new SineEase { EasingMode = EasingMode.EaseInOut }
        };
        Storyboard.SetTarget(animation, ScanMascotGlow);
        Storyboard.SetTargetProperty(animation, "Opacity");

        _mascotPulseStoryboard = new Storyboard();
        _mascotPulseStoryboard.Children.Add(animation);
        _mascotPulseStoryboard.Begin();
    }

    private void StopMascotPulse()
    {
        _mascotPulseStoryboard?.Stop();
        _mascotPulseStoryboard = null;
        ScanMascotGlow.Opacity = 0.3;
    }

    private async void BrowseButton_Click(object sender, RoutedEventArgs e)
    {
        var picker = new FileOpenPicker
        {
            ViewMode = PickerViewMode.List,
            SuggestedStartLocation = PickerLocationId.Desktop
        };
        picker.FileTypeFilter.Add("*");

        // Associate the picker with the main window (WinUI 3 requirement).
        if (App.MainWindow is not null)
            InitializeWithWindow.Initialize(picker, WindowNative.GetWindowHandle(App.MainWindow));

        var file = await picker.PickSingleFileAsync();
        if (file is not null)
            ViewModel.TargetPath = file.Path;
    }

    /// <summary>
    /// Sends the real last scan outcome to BECETTI AI as a prefilled message — the user
    /// still has to review it and tap Send; nothing is transmitted automatically here.
    /// </summary>
    private void OpenYaraEngineButton_Click(object sender, RoutedEventArgs e)
    {
        App.MainWindow?.NavigateTo("Yara", ViewModel.TargetPath);
    }

    private void AskAiAboutScan_Click(object sender, RoutedEventArgs e)
    {
        var prompt = ViewModel.BuildAiExplainPrompt();
        if (prompt is null)
            return;

        App.MainWindow?.NavigateTo("Ai", prompt);
    }
}
