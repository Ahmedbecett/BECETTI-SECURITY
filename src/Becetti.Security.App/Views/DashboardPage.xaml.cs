using Becetti.Security.App.ViewModels;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media.Animation;
using Microsoft.UI.Xaml.Navigation;

namespace Becetti.Security.App.Views;

public sealed partial class DashboardPage : Page
{
    private Storyboard? _mascotFloatStoryboard;

    public DashboardViewModel ViewModel { get; }

    public DashboardPage()
    {
        InitializeComponent();
        ViewModel = App.Services.GetRequiredService<DashboardViewModel>();
    }

    protected override async void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        await ViewModel.LoadAsync();

        if (ViewModel.EnableAnimations)
            StartMascotFloat();
    }

    private void ScanNowButton_Click(object sender, RoutedEventArgs e) =>
        App.MainWindow?.NavigateTo("Scan", null);

    private void OpenYara_Click(object sender, RoutedEventArgs e) =>
        App.MainWindow?.NavigateTo("Yara", null);

    private void OpenEdr_Click(object sender, RoutedEventArgs e) =>
        App.MainWindow?.NavigateTo("EdrCenter", null);

    private void OpenAdvancedDefense_Click(object sender, RoutedEventArgs e) =>
        App.MainWindow?.NavigateTo("AdvancedDefense", null);

    private void OpenCommandPalette_Click(object sender, RoutedEventArgs e) =>
        App.MainWindow?.OpenCommandPalette();

    private void StartMascotFloat()
    {
        if (_mascotFloatStoryboard is not null)
            return;

        var animation = new DoubleAnimation
        {
            From = -6,
            To = 6,
            Duration = new Duration(TimeSpan.FromSeconds(2.2)),
            AutoReverse = true,
            RepeatBehavior = RepeatBehavior.Forever,
            EasingFunction = new SineEase { EasingMode = EasingMode.EaseInOut }
        };
        Storyboard.SetTarget(animation, MascotTransform);
        Storyboard.SetTargetProperty(animation, "Y");

        _mascotFloatStoryboard = new Storyboard();
        _mascotFloatStoryboard.Children.Add(animation);
        _mascotFloatStoryboard.Begin();
    }
}
