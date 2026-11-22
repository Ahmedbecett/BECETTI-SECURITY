using Becetti.Security.App.ViewModels;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;
using Windows.Storage.Pickers;
using WinRT.Interop;

namespace Becetti.Security.App.Views;

public sealed partial class AdvancedDefensePage : Page
{
    public AdvancedDefenseViewModel ViewModel { get; }

    public AdvancedDefensePage()
    {
        InitializeComponent();
        ViewModel = App.Services.GetRequiredService<AdvancedDefenseViewModel>();
    }

    protected override async void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        await ViewModel.LoadAsync();
    }

    private async void BrowseForensicsFile_Click(object sender, RoutedEventArgs e)
    {
        if (App.MainWindow is null)
            return;

        var picker = new FileOpenPicker();
        picker.FileTypeFilter.Add("*");
        var hwnd = WindowNative.GetWindowHandle(App.MainWindow);
        InitializeWithWindow.Initialize(picker, hwnd);

        var file = await picker.PickSingleFileAsync();
        if (file is not null)
        {
            ViewModel.ForensicsFilePath = file.Path;
            await ViewModel.AnalyzeForensicsAsync();
        }
    }

    private async void RestoreQuarantine_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button btn && btn.Tag is string id)
            await ViewModel.RestoreQuarantineEntryAsync(id);
    }

    private async void DeleteQuarantine_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button btn && btn.Tag is string id)
            await ViewModel.DeleteQuarantineEntryAsync(id);
    }
}
