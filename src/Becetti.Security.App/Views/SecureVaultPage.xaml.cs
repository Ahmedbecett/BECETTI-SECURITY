using Becetti.Security.App.ViewModels;
using Becetti.Security.Core.Models;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;
using Windows.Storage.Pickers;
using WinRT.Interop;

namespace Becetti.Security.App.Views;

public sealed partial class SecureVaultPage : Page
{
    public SecureVaultViewModel ViewModel { get; }

    public SecureVaultPage()
    {
        InitializeComponent();
        ViewModel = App.Services.GetRequiredService<SecureVaultViewModel>();
    }

    protected override async void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        await ViewModel.InitializeAsync();
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
            ViewModel.PendingFilePath = file.Path;
    }

    private async void ExtractButton_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button { Tag: VaultItemInfo item })
            return;

        var picker = new FileSavePicker
        {
            SuggestedStartLocation = PickerLocationId.Desktop,
            SuggestedFileName = item.OriginalFileName
        };
        var extension = System.IO.Path.GetExtension(item.OriginalFileName);
        picker.FileTypeChoices.Add(
            string.IsNullOrEmpty(extension) ? "File" : extension.TrimStart('.').ToUpperInvariant() + " file",
            new List<string> { string.IsNullOrEmpty(extension) ? "." : extension });

        if (App.MainWindow is not null)
            InitializeWithWindow.Initialize(picker, WindowNative.GetWindowHandle(App.MainWindow));

        var file = await picker.PickSaveFileAsync();
        if (file is null)
            return;

        var result = await ViewModel.ExtractAsync(item.Id, file.Path);
        ViewModel.StatusMessage = result.Message;
        if (!result.Success)
            ViewModel.ErrorMessage = result.Message;
    }
}
