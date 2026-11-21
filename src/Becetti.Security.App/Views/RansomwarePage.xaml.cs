using Becetti.Security.App.ViewModels;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace Becetti.Security.App.Views;

public sealed partial class RansomwarePage : Page
{
    public RansomwareViewModel ViewModel { get; }

    public RansomwarePage()
    {
        InitializeComponent();
        ViewModel = App.Services.GetRequiredService<RansomwareViewModel>();
    }

    protected override async void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        await ViewModel.LoadAsync();
    }
}
