using System.Diagnostics;
using Becetti.Security.App.ViewModels;
using Becetti.Security.Core.Models;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace Becetti.Security.App.Views;

public sealed partial class GlobalIntelPage : Page
{
    public GlobalIntelViewModel ViewModel { get; }

    public GlobalIntelPage()
    {
        InitializeComponent();
        ViewModel = App.Services.GetRequiredService<GlobalIntelViewModel>();
        DataContext = ViewModel;
    }

    protected override async void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        if (ViewModel.PrivacyControls.Count == 0)
            await ViewModel.AuditPrivacyAsync();
    }

    private void OpenMitreUrl_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: string url } && Uri.TryCreate(url, UriKind.Absolute, out _))
        {
            try { Process.Start(new ProcessStartInfo { FileName = url, UseShellExecute = true }); }
            catch { }
        }
    }

    private async void TogglePrivacyControl_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: PrivacyControlItem item })
            await ViewModel.TogglePrivacyControlAsync(item);
    }
}
