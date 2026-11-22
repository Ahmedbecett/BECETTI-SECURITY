using System.Collections.ObjectModel;
using Becetti.Security.Core.Models;
using Becetti.Security.Core.Services;

namespace Becetti.Security.App.ViewModels;

/// <summary>Browser Security page: real installed browsers and the real SmartScreen policy.</summary>
public sealed class BrowserSecurityViewModel : ViewModelBase
{
    private readonly IBrowserSecurityService _browsers;

    private bool? _appsAndFilesEnabled;
    private bool? _edgeSmartScreenEnabled;

    public BrowserSecurityViewModel(IBrowserSecurityService browsers)
    {
        _browsers = browsers;
        RefreshCommand = new RelayCommand(LoadAsync);
    }

    public ObservableCollection<BrowserInfo> Browsers { get; } = new();

    public RelayCommand RefreshCommand { get; }

    public bool? AppsAndFilesEnabled { get => _appsAndFilesEnabled; set => SetProperty(ref _appsAndFilesEnabled, value); }
    public bool? EdgeSmartScreenEnabled { get => _edgeSmartScreenEnabled; set => SetProperty(ref _edgeSmartScreenEnabled, value); }

    public string SmartScreenSummary =>
        AppsAndFilesEnabled switch
        {
            true => "SmartScreen for apps & files: On",
            false => "SmartScreen for apps & files: Off",
            null => "SmartScreen for apps & files: Not explicitly configured"
        };

    public async Task LoadAsync()
    {
        if (IsBusy)
            return;

        IsBusy = true;
        ClearMessages();
        try
        {
            var browsersResult = await _browsers.GetInstalledBrowsersAsync();
            Browsers.Clear();
            if (browsersResult.Success && browsersResult.Value is not null)
            {
                foreach (var browser in browsersResult.Value.OrderBy(b => b.Name, StringComparer.OrdinalIgnoreCase))
                    Browsers.Add(browser);
            }
            else
            {
                ErrorMessage = browsersResult.Message;
            }

            var smartScreen = await _browsers.GetSmartScreenStatusAsync();
            if (smartScreen.Success && smartScreen.Value is not null)
            {
                AppsAndFilesEnabled = smartScreen.Value.AppsAndFilesEnabled;
                EdgeSmartScreenEnabled = smartScreen.Value.EdgeSmartScreenEnabled;
            }
            else if (string.IsNullOrWhiteSpace(ErrorMessage))
            {
                ErrorMessage = smartScreen.Message;
            }

            OnPropertyChanged(nameof(SmartScreenSummary));
            StatusMessage = $"{Browsers.Count} browser(s) detected.";
        }
        finally
        {
            IsBusy = false;
        }
    }
}
