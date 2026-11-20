using Becetti.Security.App.ViewModels;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace Becetti.Security.App.Views;

public sealed partial class ThreatsPage : Page
{
    public ThreatsViewModel ViewModel { get; }

    public ThreatsPage()
    {
        InitializeComponent();
        ViewModel = App.Services.GetRequiredService<ThreatsViewModel>();
    }

    protected override async void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        await ViewModel.LoadAsync();
    }
}
