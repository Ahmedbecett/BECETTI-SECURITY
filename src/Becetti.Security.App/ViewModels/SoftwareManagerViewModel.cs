using System.Collections.ObjectModel;
using Becetti.Security.Core.Models;
using Becetti.Security.Core.Services;

namespace Becetti.Security.App.ViewModels;

/// <summary>
/// Software Manager: the real installed-applications inventory (same source
/// as Settings &gt; Apps). Uninstalling only ever launches the application's
/// own real uninstaller after the user explicitly selects it and presses
/// Uninstall — BECETTI SECURITY never removes a program by itself.
/// </summary>
public sealed class SoftwareManagerViewModel : ViewModelBase
{
    private readonly ISoftwareManagerService _software;
    private readonly IEventLogService _events;

    private InstalledAppInfo? _selectedApp;

    public SoftwareManagerViewModel(ISoftwareManagerService software, IEventLogService events)
    {
        _software = software;
        _events = events;
        RefreshCommand = new RelayCommand(LoadAsync);
        UninstallCommand = new RelayCommand(UninstallSelectedAsync);
    }

    public ObservableCollection<InstalledAppInfo> Apps { get; } = new();

    public RelayCommand RefreshCommand { get; }
    public RelayCommand UninstallCommand { get; }

    public InstalledAppInfo? SelectedApp
    {
        get => _selectedApp;
        set
        {
            if (SetProperty(ref _selectedApp, value))
                OnPropertyChanged(nameof(CanUninstallSelected));
        }
    }

    public bool CanUninstallSelected => SelectedApp?.CanUninstall ?? false;

    public async Task LoadAsync()
    {
        if (IsBusy)
            return;

        IsBusy = true;
        ClearMessages();
        try
        {
            var result = await _software.GetInstalledAppsAsync();
            Apps.Clear();

            if (!result.Success || result.Value is null)
            {
                ErrorMessage = result.Message;
                StatusMessage = "Installed application list unavailable.";
                return;
            }

            foreach (var app in result.Value)
                Apps.Add(app);

            StatusMessage = result.Message;
        }
        finally
        {
            IsBusy = false;
        }
    }

    private async Task UninstallSelectedAsync()
    {
        if (IsBusy)
            return;

        if (SelectedApp is null)
        {
            ErrorMessage = "Select an application first.";
            return;
        }

        var app = SelectedApp;
        ClearMessages();
        var result = _software.LaunchUninstaller(app);
        if (result.Success)
        {
            StatusMessage = result.Message;
            await _events.RecordAsync("software.uninstall.launched", result.Message, true, app.Name);
        }
        else
        {
            ErrorMessage = result.Message;
            await _events.RecordAsync("software.uninstall.failed", result.Message, false, app.Name);
        }
    }
}
