using Becetti.Security.App.ViewModels;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;
using Windows.Storage.Pickers;
using WinRT.Interop;

namespace Becetti.Security.App.Views;

public sealed partial class NetworkMonitorPage : Page
{
    public NetworkMonitorViewModel ViewModel { get; }

    public NetworkMonitorPage()
    {
        InitializeComponent();
        ViewModel = App.Services.GetRequiredService<NetworkMonitorViewModel>();
    }

    protected override async void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        await ViewModel.LoadAsync();
    }

    private async void BrowseExeToBlock_Click(object sender, RoutedEventArgs e)
    {
        if (App.MainWindow is null)
            return;

        var picker = new FileOpenPicker();
        picker.FileTypeFilter.Add(".exe");
        InitializeWithWindow.Initialize(picker, WindowNative.GetWindowHandle(App.MainWindow));

        var file = await picker.PickSingleFileAsync();
        if (file is not null)
            ViewModel.AppPathToBlock = file.Path;
    }

    private async void UnblockApp_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: string ruleName })
            await ViewModel.UnblockRuleAsync(ruleName);
    }
}
