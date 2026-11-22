using Becetti.Security.App.ViewModels;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace Becetti.Security.App.Views;

public sealed partial class SoftwareManagerPage : Page
{
    public SoftwareManagerViewModel ViewModel { get; }

    public SoftwareManagerPage()
    {
        InitializeComponent();
        ViewModel = App.Services.GetRequiredService<SoftwareManagerViewModel>();
    }

    protected override async void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        await ViewModel.LoadAsync();
    }
}
