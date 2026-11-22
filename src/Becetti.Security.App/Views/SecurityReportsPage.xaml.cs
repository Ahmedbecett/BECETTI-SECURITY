using Becetti.Security.App.ViewModels;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;
using Windows.Storage.Pickers;
using WinRT.Interop;

namespace Becetti.Security.App.Views;

public sealed partial class SecurityReportsPage : Page
{
    public SecurityReportsViewModel ViewModel { get; }

    public SecurityReportsPage()
    {
        InitializeComponent();
        ViewModel = App.Services.GetRequiredService<SecurityReportsViewModel>();
    }

    protected override async void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        await ViewModel.LoadAsync();
    }

    private async void SaveAsPdf_Click(object sender, RoutedEventArgs e)
    {
        var picker = new FileSavePicker
        {
            SuggestedStartLocation = PickerLocationId.DocumentsLibrary,
            SuggestedFileName = $"BecettiSecurity-Report-{DateTimeOffset.Now:yyyyMMdd-HHmm}"
        };
        picker.FileTypeChoices.Add("PDF Document", new List<string> { ".pdf" });

        if (App.MainWindow is not null)
            InitializeWithWindow.Initialize(picker, WindowNative.GetWindowHandle(App.MainWindow));

        var file = await picker.PickSaveFileAsync();
        if (file is null)
            return;

        try
        {
            var bytes = ViewModel.RenderPdf();
            await System.IO.File.WriteAllBytesAsync(file.Path, bytes);
            ViewModel.StatusMessage = $"Report saved to {file.Path}.";
        }
        catch (Exception ex)
        {
            ViewModel.ErrorMessage = $"Could not save the PDF: {ex.Message}";
        }
    }

    private async void SaveAsText_Click(object sender, RoutedEventArgs e)
    {
        var picker = new FileSavePicker
        {
            SuggestedStartLocation = PickerLocationId.DocumentsLibrary,
            SuggestedFileName = $"BecettiSecurity-Report-{DateTimeOffset.Now:yyyyMMdd-HHmm}"
        };
        picker.FileTypeChoices.Add("Text File", new List<string> { ".txt" });

        if (App.MainWindow is not null)
            InitializeWithWindow.Initialize(picker, WindowNative.GetWindowHandle(App.MainWindow));

        var file = await picker.PickSaveFileAsync();
        if (file is null)
            return;

        try
        {
            var text = ViewModel.RenderText();
            await System.IO.File.WriteAllTextAsync(file.Path, text);
            ViewModel.StatusMessage = $"Report saved to {file.Path}.";
        }
        catch (Exception ex)
        {
            ViewModel.ErrorMessage = $"Could not save the report: {ex.Message}";
        }
    }
}
