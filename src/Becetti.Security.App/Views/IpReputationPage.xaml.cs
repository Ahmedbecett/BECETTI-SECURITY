using Becetti.Security.App.ViewModels;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace Becetti.Security.App.Views;

public sealed partial class IpReputationPage : Page
{
    public IpReputationViewModel ViewModel { get; }

    public IpReputationPage()
    {
        InitializeComponent();
        ViewModel = App.Services.GetRequiredService<IpReputationViewModel>();
    }

    protected override async void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        await ViewModel.InitializeAsync();
    }
}
