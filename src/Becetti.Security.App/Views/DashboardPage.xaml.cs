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

        // Decorative only: a gentle float on the mascot. Never used to imply a
        // scan/update is running — those states have their own real progress UI.
        if (ViewModel.EnableAnimations)
            StartMascotFloat();
    }

    private void ScanNowButton_Click(object sender, RoutedEventArgs e)
    {
        Frame.Navigate(typeof(ScanPage), null, new EntranceNavigationTransitionInfo());
    }

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
