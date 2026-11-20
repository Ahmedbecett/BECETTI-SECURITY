using Becetti.Security.App.ViewModels;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace Becetti.Security.App.Views;

public sealed partial class UpdatesPage : Page
{
    public UpdatesViewModel ViewModel { get; }

    public UpdatesPage()
    {
        InitializeComponent();
        ViewModel = App.Services.GetRequiredService<UpdatesViewModel>();
    }

    protected override async void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        await ViewModel.LoadSignaturesAsync();
    }
}
