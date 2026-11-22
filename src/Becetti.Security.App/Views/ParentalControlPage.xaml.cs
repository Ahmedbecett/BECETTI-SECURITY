using Becetti.Security.App.ViewModels;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace Becetti.Security.App.Views;

public sealed partial class ParentalControlPage : Page
{
    public ParentalControlViewModel ViewModel { get; }

    public ParentalControlPage()
    {
        InitializeComponent();
        ViewModel = App.Services.GetRequiredService<ParentalControlViewModel>();
    }

    protected override async void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        await ViewModel.InitializeAsync();
    }

    private async void UnblockButton_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: string domain })
            await ViewModel.UnblockAsync(domain);
    }
}
