using Becetti.Security.App.ViewModels;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace Becetti.Security.App.Views;

public sealed partial class UsbProtectionPage : Page
{
    public UsbProtectionViewModel ViewModel { get; }

    public UsbProtectionPage()
    {
        InitializeComponent();
        ViewModel = App.Services.GetRequiredService<UsbProtectionViewModel>();
    }

    protected override async void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        await ViewModel.LoadAsync();
    }

    /// <summary>
    /// Sends the selected real removable drive's path to Smart Scan, prefilling the
    /// Custom Scan target — the user still has to press Start Custom Scan themselves.
    /// </summary>
    private void ScanSelectedDrive_Click(object sender, RoutedEventArgs e)
    {
        if (ViewModel.SelectedDrive is null)
        {
            ViewModel.ErrorMessage = "Select a connected drive first.";
            return;
        }

        App.MainWindow?.NavigateTo("Scan", ViewModel.SelectedDrive.RootPath);
    }
}
