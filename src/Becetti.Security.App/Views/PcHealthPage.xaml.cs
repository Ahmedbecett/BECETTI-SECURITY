using Becetti.Security.App.ViewModels;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace Becetti.Security.App.Views;

public sealed partial class PcHealthPage : Page
{
    public PcHealthViewModel ViewModel { get; }

    public PcHealthPage()
    {
        InitializeComponent();
        ViewModel = App.Services.GetRequiredService<PcHealthViewModel>();
    }

    protected override async void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        await ViewModel.LoadAsync();
    }
}
