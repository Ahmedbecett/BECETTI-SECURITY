using Becetti.Security.App.ViewModels;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace Becetti.Security.App.Views;

public sealed partial class CloudSyncPage : Page
{
    public CloudSyncViewModel ViewModel { get; }

    public CloudSyncPage()
    {
        InitializeComponent();
        ViewModel = App.Services.GetRequiredService<CloudSyncViewModel>();
    }

    protected override async void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        await ViewModel.LoadAsync();
    }
}
