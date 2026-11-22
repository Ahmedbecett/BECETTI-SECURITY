using Becetti.Security.App.ViewModels;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace Becetti.Security.App.Views;

public sealed partial class DataBreachPage : Page
{
    public DataBreachViewModel ViewModel { get; }

    public DataBreachPage()
    {
        InitializeComponent();
        ViewModel = App.Services.GetRequiredService<DataBreachViewModel>();
    }

    protected override async void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        await ViewModel.InitializeAsync();
    }

    private void PasswordInputBox_PasswordChanged(object sender, RoutedEventArgs e)
    {
        if (sender is PasswordBox box)
            ViewModel.PasswordInput = box.Password;
    }
}
