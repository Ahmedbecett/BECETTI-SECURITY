using Becetti.Security.App.ViewModels;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace Becetti.Security.App.Views;

public sealed partial class BrowserSecurityPage : Page
{
    public BrowserSecurityViewModel ViewModel { get; }

    public BrowserSecurityPage()
    {
        InitializeComponent();
        ViewModel = App.Services.GetRequiredService<BrowserSecurityViewModel>();
    }

    protected override async void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        await ViewModel.LoadAsync();
    }
}
