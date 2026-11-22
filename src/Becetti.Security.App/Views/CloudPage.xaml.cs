using Becetti.Security.App.ViewModels;
using Becetti.Security.Core.Models;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;
using Windows.Storage.Pickers;
using WinRT.Interop;

namespace Becetti.Security.App.Views;

public sealed partial class CloudPage : Page
{
    public CloudViewModel ViewModel { get; }

    public CloudPage()
    {
        InitializeComponent();
        ViewModel = App.Services.GetRequiredService<CloudViewModel>();
    }

    protected override async void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        await ViewModel.InitializeAsync();
    }

    private void PasswordBox_PasswordChanged(object sender, RoutedEventArgs e)
    {
        if (sender is PasswordBox box)
            ViewModel.Password = box.Password;
    }

    private async void RemoveDeviceButton_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: DeviceSummary device })
            await ViewModel.RemoveDeviceAsync(device);
    }

    private async void BrowseButton_Click(object sender, RoutedEventArgs e)
    {
        var picker = new FileOpenPicker
        {
            ViewMode = PickerViewMode.List,
            SuggestedStartLocation = PickerLocationId.Desktop
        };
        picker.FileTypeFilter.Add("*");

        if (App.MainWindow is not null)
            InitializeWithWindow.Initialize(picker, WindowNative.GetWindowHandle(App.MainWindow));

        var file = await picker.PickSingleFileAsync();
        if (file is not null)
            ViewModel.ReputationFilePath = file.Path;
    }
}
