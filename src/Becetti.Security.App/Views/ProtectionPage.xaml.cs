using Becetti.Security.App.ViewModels;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace Becetti.Security.App.Views;

public sealed partial class ProtectionPage : Page
{
    public ProtectionViewModel ViewModel { get; }

    public ProtectionPage()
    {
        InitializeComponent();
        ViewModel = App.Services.GetRequiredService<ProtectionViewModel>();
    }

    protected override async void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        await ViewModel.LoadAsync();
    }
}
