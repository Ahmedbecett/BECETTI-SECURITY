using Becetti.Security.App.ViewModels;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml.Controls;

namespace Becetti.Security.App.Views;

public sealed partial class SettingsPage : Page
{
    public SettingsViewModel ViewModel { get; }

    public SettingsPage()
    {
        InitializeComponent();
        ViewModel = App.Services.GetRequiredService<SettingsViewModel>();
    }

    private void AppLockPinBox_PasswordChanged(object sender, Microsoft.UI.Xaml.RoutedEventArgs e)
    {
        if (sender is PasswordBox pb)
            ViewModel.NewAppLockPin = pb.Password;
    }
}
