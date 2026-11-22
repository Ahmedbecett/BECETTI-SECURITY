using Becetti.Security.App.ViewModels;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media.Animation;
using Microsoft.UI.Xaml.Navigation;

namespace Becetti.Security.App.Views;

public sealed partial class EmergencyCenterPage : Page
{
    public EmergencyCenterViewModel ViewModel { get; }

    public EmergencyCenterPage()
    {
        InitializeComponent();
        ViewModel = App.Services.GetRequiredService<EmergencyCenterViewModel>();
    }

    protected override async void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        await ViewModel.LoadAsync();
    }

    private void OpenThreats_Click(object sender, RoutedEventArgs e)
    {
        Frame.Navigate(typeof(ThreatsPage), null, new EntranceNavigationTransitionInfo());
    }

    private void AskBecettiAi_Click(object sender, RoutedEventArgs e)
    {
        Frame.Navigate(typeof(BecettiAiPage), null, new EntranceNavigationTransitionInfo());
    }
}
