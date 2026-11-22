using Becetti.Security.App.ViewModels;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace Becetti.Security.App.Views;

public sealed partial class WifiSecurityPage : Page
{
    public WifiSecurityViewModel ViewModel { get; }

    public WifiSecurityPage()
    {
        InitializeComponent();
        ViewModel = App.Services.GetRequiredService<WifiSecurityViewModel>();
    }

    protected override async void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        await ViewModel.LoadAsync();
    }
}
