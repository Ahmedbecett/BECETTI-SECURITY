using Becetti.Security.App.ViewModels;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace Becetti.Security.App.Views;

public sealed partial class StartupManagerPage : Page
{
    public StartupManagerViewModel ViewModel { get; }

    public StartupManagerPage()
    {
        InitializeComponent();
        ViewModel = App.Services.GetRequiredService<StartupManagerViewModel>();
    }

    protected override async void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        await ViewModel.LoadAsync();
    }
}
