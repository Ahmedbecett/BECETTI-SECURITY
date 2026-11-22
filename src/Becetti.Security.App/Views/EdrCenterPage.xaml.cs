using Becetti.Security.App.ViewModels;
using Becetti.Security.Core.Models;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;
using Windows.Storage.Pickers;
using WinRT.Interop;

namespace Becetti.Security.App.Views;

public sealed partial class EdrCenterPage : Page
{
    public EdrCenterViewModel ViewModel { get; }

    public EdrCenterPage()
    {
        ViewModel = App.Services.GetRequiredService<EdrCenterViewModel>();
        InitializeComponent();
        DataContext = ViewModel;
    }

    protected override async void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        await ViewModel.LoadAsync();
    }

    private async void RemediateHardening_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: HardeningCheckItem check })
            await ViewModel.RemediateHardeningCheckAsync(check);
    }

    private void AskAiAboutPersistence_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: PersistenceEntry entry })
            App.MainWindow?.NavigateTo("Ai", ViewModel.BuildPersistenceAiPrompt(entry));
    }

    private void AskAiAboutUrl_Click(object sender, RoutedEventArgs e)
    {
        if (!string.IsNullOrWhiteSpace(ViewModel.UrlToInspect))
            App.MainWindow?.NavigateTo("Ai", ViewModel.BuildUrlAiPrompt());
    }

    private void ScanPersistenceWithYara_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: string path } && !string.IsNullOrWhiteSpace(path))
            App.MainWindow?.NavigateTo("Yara", "AUTO:" + path);
    }

    private async void DisablePersistenceTask_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: PersistenceEntry entry })
            await ViewModel.DisableTaskAsync(entry);
    }

    private void AskAiAboutScript_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: string cmd } && !string.IsNullOrWhiteSpace(cmd))
            App.MainWindow?.NavigateTo("Ai", ViewModel.BuildScriptAiPrompt(cmd));
    }

    private void AskAiAboutDecoded_Click(object sender, RoutedEventArgs e)
    {
        var payload = string.IsNullOrWhiteSpace(ViewModel.DecodedBase64Output)
            ? ViewModel.Base64Input
            : ViewModel.DecodedBase64Output;

        if (!string.IsNullOrWhiteSpace(payload))
            App.MainWindow?.NavigateTo("Ai", ViewModel.BuildScriptAiPrompt(payload));
    }

    private async void AddFimFile_Click(object sender, RoutedEventArgs e)
    {
        var picker = new FileOpenPicker();
        picker.FileTypeFilter.Add("*");
        if (App.MainWindow is not null)
        {
            var hwnd = WindowNative.GetWindowHandle(App.MainWindow);
            InitializeWithWindow.Initialize(picker, hwnd);
        }

        var file = await picker.PickSingleFileAsync();
        if (file is not null)
            await ViewModel.AddFimFileAsync(file.Path);
    }

    private async void RebaselineFim_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: string path })
            await ViewModel.RebaselineFimFileAsync(path);
    }

    private async void UntrackFim_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: string path })
            await ViewModel.UntrackFimFileAsync(path);
    }
}
