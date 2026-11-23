using Becetti.Security.App.ViewModels;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;
using Windows.Storage.Pickers;
using WinRT.Interop;

namespace Becetti.Security.App.Views;

public sealed partial class SocOperationsPage : Page
{
    public SocOperationsViewModel ViewModel { get; }

    public SocOperationsPage()
    {
        InitializeComponent();
        ViewModel = App.Services.GetRequiredService<SocOperationsViewModel>();
        DataContext = ViewModel;
    }

    protected override async void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        try
        {
            await ViewModel.InitializeAsync();
        }
        catch (Exception ex)
        {
            ViewModel.ErrorMessage = ex.Message;
        }
    }

    private async void OnImportSigmaYamlClick(object sender, RoutedEventArgs e)
    {
        try
        {
            var picker = new FileOpenPicker();
            picker.FileTypeFilter.Add(".yml");
            picker.FileTypeFilter.Add(".yaml");
            if (App.MainWindow is not null)
                InitializeWithWindow.Initialize(picker, WindowNative.GetWindowHandle(App.MainWindow));

            var file = await picker.PickSingleFileAsync();
            if (file is not null)
                await ViewModel.ImportSigmaYamlAsync(file.Path);
        }
        catch (Exception ex)
        {
            ViewModel.ErrorMessage = ex.Message;
        }
    }

    private async void OnOpenEmlFileClick(object sender, RoutedEventArgs e)
    {
        try
        {
            var picker = new FileOpenPicker();
            picker.FileTypeFilter.Add(".eml");
            picker.FileTypeFilter.Add(".txt");
            if (App.MainWindow is not null)
                InitializeWithWindow.Initialize(picker, WindowNative.GetWindowHandle(App.MainWindow));

            var file = await picker.PickSingleFileAsync();
            if (file is not null)
                await ViewModel.AnalyzeEmlFileAsync(file.Path);
        }
        catch (Exception ex)
        {
            ViewModel.ErrorMessage = ex.Message;
        }
    }
}
