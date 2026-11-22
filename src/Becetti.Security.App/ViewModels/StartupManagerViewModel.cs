using System.Collections.ObjectModel;
using Becetti.Security.Core.Models;
using Becetti.Security.Core.Services;

namespace Becetti.Security.App.ViewModels;

/// <summary>
/// Startup Manager: lists real Windows Run-key startup entries (the same
/// model Task Manager's "Startup apps" tab uses) and enables/disables them
/// through the real StartupApproved registry convention, re-verified after
/// every change. No performance "impact" score is shown — Windows does not
/// expose one through any stable public API.
/// </summary>
public sealed class StartupManagerViewModel : ViewModelBase
{
    private readonly IStartupManagerService _startup;
    private readonly IEventLogService _events;

    private StartupItemInfo? _selectedItem;

    public StartupManagerViewModel(IStartupManagerService startup, IEventLogService events)
    {
        _startup = startup;
        _events = events;
        RefreshCommand = new RelayCommand(LoadAsync);
        EnableCommand = new RelayCommand(() => SetEnabledAsync(true));
        DisableCommand = new RelayCommand(() => SetEnabledAsync(false));
    }

    public ObservableCollection<StartupItemInfo> Items { get; } = new();

    public RelayCommand RefreshCommand { get; }
    public RelayCommand EnableCommand { get; }
    public RelayCommand DisableCommand { get; }

    public StartupItemInfo? SelectedItem
    {
        get => _selectedItem;
        set
        {
            if (SetProperty(ref _selectedItem, value))
            {
                OnPropertyChanged(nameof(HasSelection));
                OnPropertyChanged(nameof(SelectionNeedsElevation));
            }
        }
    }

    public bool HasSelection => SelectedItem is not null;

    /// <summary>True when the selected item is machine-wide and this process is not elevated.</summary>
    public bool SelectionNeedsElevation => SelectedItem is { RequiresElevationToChange: true } && !ElevationHelper.IsElevated();

    public async Task LoadAsync()
    {
        if (IsBusy)
            return;

        IsBusy = true;
        ClearMessages();
        try
        {
            var result = await _startup.GetStartupItemsAsync();
            Items.Clear();

            if (!result.Success || result.Value is null)
            {
                ErrorMessage = result.Message;
                StatusMessage = "Startup item list unavailable.";
                return;
            }

            foreach (var item in result.Value)
                Items.Add(item);

            StatusMessage = Items.Count == 0
                ? "No registry-based startup entries were found."
                : $"{Items.Count} startup item(s) read from the registry.";
        }
        finally
        {
            IsBusy = false;
        }
    }

    private async Task SetEnabledAsync(bool enable)
    {
        if (IsBusy)
            return;

        if (SelectedItem is null)
        {
            ErrorMessage = "Select a startup item first.";
            return;
        }

        var item = SelectedItem;
        IsBusy = true;
        ClearMessages();
        try
        {
            var result = await _startup.SetEnabledAsync(item, enable);
            if (result.Success)
            {
                StatusMessage = result.Message;
                await _events.RecordAsync(enable ? "startup.enabled" : "startup.disabled", result.Message, true, item.Name);
            }
            else
            {
                ErrorMessage = result.Message;
                await _events.RecordAsync("startup.change.failed", result.Message, false, item.Name);
            }
        }
        finally
        {
            IsBusy = false;
        }

        await LoadAsync();
    }
}
