using Becetti.Security.App.ViewModels;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;
using Windows.Storage.Pickers;
using WinRT.Interop;

namespace Becetti.Security.App.Views;

public sealed partial class InfrastructureCompliancePage : Page
{
    public InfrastructureComplianceViewModel ViewModel { get; }

    public InfrastructureCompliancePage()
    {
        InitializeComponent();
        ViewModel = App.Services.GetRequiredService<InfrastructureComplianceViewModel>();
        DataContext = ViewModel;
    }

    protected override async void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        try
        {
            await ViewModel.RefreshVaultAsync();
        }
        catch (Exception ex)
        {
            ViewModel.ErrorMessage = ex.Message;
        }
    }

    private async void OnPickVaultFileClick(object sender, RoutedEventArgs e)
    {
        try
        {
            var picker = new FileOpenPicker();
            picker.FileTypeFilter.Add("*");
            if (App.MainWindow is not null)
                InitializeWithWindow.Initialize(picker, WindowNative.GetWindowHandle(App.MainWindow));

            var file = await picker.PickSingleFileAsync();
            if (file is not null)
                ViewModel.VaultSourcePath = file.Path;
        }
        catch (Exception ex)
        {
            ViewModel.ErrorMessage = ex.Message;
        }
    }

    private async void OnPickVaultFolderClick(object sender, RoutedEventArgs e)
    {
        try
        {
            var picker = new FolderPicker();
            picker.FileTypeFilter.Add("*");
            if (App.MainWindow is not null)
                InitializeWithWindow.Initialize(picker, WindowNative.GetWindowHandle(App.MainWindow));

            var folder = await picker.PickSingleFolderAsync();
            if (folder is not null)
                ViewModel.VaultSourcePath = folder.Path;
        }
        catch (Exception ex)
        {
            ViewModel.ErrorMessage = ex.Message;
        }
    }

    private async void OnUnsealVaultItemClick(object sender, RoutedEventArgs e)
    {
        try
        {
            var picker = new FolderPicker();
            picker.FileTypeFilter.Add("*");
            if (App.MainWindow is not null)
                InitializeWithWindow.Initialize(picker, WindowNative.GetWindowHandle(App.MainWindow));

            var folder = await picker.PickSingleFolderAsync();
            if (folder is not null)
                await ViewModel.UnsealSelectedVaultItemAsync(folder.Path);
        }
        catch (Exception ex)
        {
            ViewModel.ErrorMessage = ex.Message;
        }
    }
}
