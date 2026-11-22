using Becetti.Security.App.ViewModels;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace Becetti.Security.App.Views;

public sealed partial class BackupAdvisorPage : Page
{
    public BackupAdvisorViewModel ViewModel { get; }

    public BackupAdvisorPage()
    {
        InitializeComponent();
        ViewModel = App.Services.GetRequiredService<BackupAdvisorViewModel>();
    }

    protected override async void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        await ViewModel.LoadAsync();
    }
}
