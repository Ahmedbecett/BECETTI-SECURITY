using Becetti.Security.App.ViewModels;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;
using Windows.Storage.Pickers;
using Windows.System;
using WinRT.Interop;

namespace Becetti.Security.App.Views;

public sealed partial class ThreatIntelligencePage : Page
{
    public ThreatIntelligenceViewModel ViewModel { get; }

    public ThreatIntelligencePage()
    {
        InitializeComponent();
        ViewModel = App.Services.GetRequiredService<ThreatIntelligenceViewModel>();
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
            ViewModel.SelectedFilePath = file.Path;
    }

    private async void OpenPermalinkButton_Click(object sender, RoutedEventArgs e)
    {
        var permalink = ViewModel.CurrentReport?.Permalink;
        if (string.IsNullOrWhiteSpace(permalink) || !Uri.TryCreate(permalink, UriKind.Absolute, out var uri))
            return;

        await Launcher.LaunchUriAsync(uri);
    }
}
