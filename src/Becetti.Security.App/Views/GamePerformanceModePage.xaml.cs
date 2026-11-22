using Becetti.Security.App.ViewModels;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace Becetti.Security.App.Views;

public sealed partial class GamePerformanceModePage : Page
{
    public GamePerformanceModeViewModel ViewModel { get; }

    public GamePerformanceModePage()
    {
        InitializeComponent();
        ViewModel = App.Services.GetRequiredService<GamePerformanceModeViewModel>();
    }

    protected override async void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        await ViewModel.InitializeAsync();
    }
}
