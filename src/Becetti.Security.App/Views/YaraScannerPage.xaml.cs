using Becetti.Security.App.ViewModels;
using Becetti.Security.Core.Models;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;
using Windows.Storage;
using Windows.Storage.Pickers;
using WinRT.Interop;

namespace Becetti.Security.App.Views;

public sealed partial class YaraScannerPage : Page
{
    public YaraScannerViewModel ViewModel { get; }

    public YaraScannerPage()
    {
        InitializeComponent();
        ViewModel = App.Services.GetRequiredService<YaraScannerViewModel>();
    }

    protected override async void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        if (e.Parameter is string prefillPath && !string.IsNullOrWhiteSpace(prefillPath))
            ViewModel.TargetPath = prefillPath;

        await ViewModel.InitializeAsync();
    }

    private async void BrowseFileButton_Click(object sender, RoutedEventArgs e)
    {
        var picker = new FileOpenPicker
        {
            ViewMode = PickerViewMode.List,
            SuggestedStartLocation = PickerLocationId.Desktop
        };
        picker.FileTypeFilter.Add("*");
        InitializePicker(picker);

        var file = await picker.PickSingleFileAsync();
        if (file is not null)
            ViewModel.TargetPath = file.Path;
    }

    private async void BrowseFolderButton_Click(object sender, RoutedEventArgs e)
    {
        var picker = new FolderPicker
        {
            ViewMode = PickerViewMode.List,
            SuggestedStartLocation = PickerLocationId.Desktop
        };
        picker.FileTypeFilter.Add("*");
        InitializePicker(picker);

        var folder = await picker.PickSingleFolderAsync();
        if (folder is not null)
            ViewModel.TargetPath = folder.Path;
    }

    private async void ImportRuleButton_Click(object sender, RoutedEventArgs e)
    {
        var picker = new FileOpenPicker
        {
            ViewMode = PickerViewMode.List,
            SuggestedStartLocation = PickerLocationId.DocumentsLibrary
        };
        picker.FileTypeFilter.Add(".yar");
        picker.FileTypeFilter.Add(".yara");
        InitializePicker(picker);

        var file = await picker.PickSingleFileAsync();
        if (file is not null)
            await ViewModel.ImportRuleFileAsync(file.Path);
    }

    private async void ToggleRuleButton_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: YaraRuleFileInfo rule })
            await ViewModel.ToggleRuleEnabledAsync(rule);
    }

    private async void RemoveRuleButton_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: YaraRuleFileInfo rule })
            await ViewModel.RemoveRuleFileAsync(rule);
    }

    private async void SaveTextReport_Click(object sender, RoutedEventArgs e)
    {
        var text = ViewModel.GetTextReport();
        if (text is null)
            return;

        var picker = new FileSavePicker
        {
            SuggestedStartLocation = PickerLocationId.DocumentsLibrary,
            SuggestedFileName = $"BECETTI-YARA-Report-{DateTime.Now:yyyyMMdd-HHmmss}"
        };
        picker.FileTypeChoices.Add("Text Report", new List<string> { ".txt" });
        InitializePicker(picker);

        var file = await picker.PickSaveFileAsync();
        if (file is not null)
        {
            await FileIO.WriteTextAsync(file, text);
            ViewModel.StatusMessage = $"Saved YARA text report to {file.Path}";
        }
    }

    private async void SaveJsonReport_Click(object sender, RoutedEventArgs e)
    {
        var json = ViewModel.GetJsonReport();
        if (json is null)
            return;

        var picker = new FileSavePicker
        {
            SuggestedStartLocation = PickerLocationId.DocumentsLibrary,
            SuggestedFileName = $"BECETTI-YARA-Report-{DateTime.Now:yyyyMMdd-HHmmss}"
        };
        picker.FileTypeChoices.Add("JSON Report", new List<string> { ".json" });
        InitializePicker(picker);

        var file = await picker.PickSaveFileAsync();
        if (file is not null)
        {
            await FileIO.WriteTextAsync(file, json);
            ViewModel.StatusMessage = $"Saved YARA JSON report to {file.Path}";
        }
    }

    private async void SavePdfReport_Click(object sender, RoutedEventArgs e)
    {
        var pdfBytes = ViewModel.GetPdfReportBytes();
        if (pdfBytes is null)
            return;

        var picker = new FileSavePicker
        {
            SuggestedStartLocation = PickerLocationId.DocumentsLibrary,
            SuggestedFileName = $"BECETTI-YARA-Report-{DateTime.Now:yyyyMMdd-HHmmss}"
        };
        picker.FileTypeChoices.Add("PDF Document", new List<string> { ".pdf" });
        InitializePicker(picker);

        var file = await picker.PickSaveFileAsync();
        if (file is not null)
        {
            await FileIO.WriteBytesAsync(file, pdfBytes);
            ViewModel.StatusMessage = $"Saved YARA PDF report to {file.Path}";
        }
    }

    private void AskAiAboutYara_Click(object sender, RoutedEventArgs e)
    {
        var prompt = ViewModel.BuildAiExplainPrompt();
        if (prompt is not null)
            App.MainWindow?.NavigateTo("Ai", prompt);
    }

    private static void InitializePicker(object picker)
    {
        if (App.MainWindow is not null)
            InitializeWithWindow.Initialize(picker, WindowNative.GetWindowHandle(App.MainWindow));
    }
}
