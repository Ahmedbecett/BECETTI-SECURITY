using Becetti.Security.App.ViewModels;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace Becetti.Security.App.Views;

public sealed partial class IdentityProtectionPage : Page
{
    public IdentityProtectionViewModel ViewModel { get; }

    public IdentityProtectionPage()
    {
        InitializeComponent();
        ViewModel = App.Services.GetRequiredService<IdentityProtectionViewModel>();
    }

    protected override async void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        await ViewModel.LoadAsync();
    }
}
