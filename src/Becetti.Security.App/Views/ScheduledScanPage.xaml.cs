using Becetti.Security.App.ViewModels;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace Becetti.Security.App.Views;

public sealed partial class ScheduledScanPage : Page
{
    public ScheduledScanViewModel ViewModel { get; }

    public ScheduledScanPage()
    {
        InitializeComponent();
        ViewModel = App.Services.GetRequiredService<ScheduledScanViewModel>();
    }

    protected override async void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        await ViewModel.LoadAsync();
    }
}
