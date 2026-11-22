using Becetti.Security.App.ViewModels;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Windows.Storage.Pickers;
using WinRT.Interop;

namespace Becetti.Security.App.Views;

public sealed partial class ProactiveDefensePage : Page
{
    public ProactiveDefenseViewModel ViewModel { get; }

    public ProactiveDefensePage()
    {
        InitializeComponent();
        ViewModel = App.Services.GetRequiredService<ProactiveDefenseViewModel>();
        DataContext = ViewModel;
    }

    private void BreachPasswordBox_PasswordChanged(object sender, RoutedEventArgs e)
    {
        if (sender is PasswordBox pb)
            ViewModel.PasswordToCheck = pb.Password;
    }

    private async void BrowseShredFile_Click(object sender, RoutedEventArgs e)
    {
        if (App.MainWindow is null) return;
        var picker = new FileOpenPicker();
        picker.FileTypeFilter.Add("*");
        InitializeWithWindow.Initialize(picker, WindowNative.GetWindowHandle(App.MainWindow));
        var file = await picker.PickSingleFileAsync();
        if (file is not null)
            ViewModel.ShredFilePath = file.Path;
    }

    private async void ImportPolicy_Click(object sender, RoutedEventArgs e)
    {
        if (App.MainWindow is null) return;
        var picker = new FileOpenPicker();
        picker.FileTypeFilter.Add(".json");
        InitializeWithWindow.Initialize(picker, WindowNative.GetWindowHandle(App.MainWindow));
        var file = await picker.PickSingleFileAsync();
        if (file is not null)
            await ViewModel.ImportPolicyFromFileAsync(file.Path);
    }
}
