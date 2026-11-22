using Becetti.Security.App.ViewModels;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace Becetti.Security.App.Views;

public sealed partial class DriverMonitorPage : Page
{
    public DriverMonitorViewModel ViewModel { get; }

    public DriverMonitorPage()
    {
        InitializeComponent();
        ViewModel = App.Services.GetRequiredService<DriverMonitorViewModel>();
    }

    protected override async void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        await ViewModel.LoadAsync();
    }
}
