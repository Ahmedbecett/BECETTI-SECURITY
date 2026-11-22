using Becetti.Security.Core.Models;
using Becetti.Security.Core.Services;

namespace Becetti.Security.App.ViewModels;

/// <summary>
/// Scheduled Scan page: manages a real Windows Scheduled Task (via
/// IScheduledScanService) that runs a genuine Defender scan.
/// </summary>
public sealed class ScheduledScanViewModel : ViewModelBase
{
    private readonly IScheduledScanService _scheduler;

    private ScheduledScanInfo _info = new();
    private double _selectedHour = 3;
    private bool _fullScan;

    public ScheduledScanViewModel(IScheduledScanService scheduler)
    {
        _scheduler = scheduler;
        RefreshCommand = new RelayCommand(LoadAsync);
        ScheduleCommand = new RelayCommand(ScheduleAsync);
        RemoveCommand = new RelayCommand(RemoveAsync);
    }

    public RelayCommand RefreshCommand { get; }
    public RelayCommand ScheduleCommand { get; }
    public RelayCommand RemoveCommand { get; }

    public ScheduledScanInfo Info { get => _info; set => SetProperty(ref _info, value); }

    public double SelectedHour { get => _selectedHour; set => SetProperty(ref _selectedHour, value); }
    public bool FullScan { get => _fullScan; set => SetProperty(ref _fullScan, value); }

    public string Summary => Info.Exists
        ? $"{Info.ScanType} scan scheduled — {Info.ScheduleDescription ?? "schedule unknown"}. " +
          $"Next run: {(Info.NextRunTime is { } next ? next.ToString("yyyy-MM-dd HH:mm") : "unknown")}."
        : "No scheduled scan is currently configured.";

    public async Task LoadAsync()
    {
        if (IsBusy)
            return;

        IsBusy = true;
        ClearMessages();
        try
        {
            await RefreshStatusAsync().ConfigureAwait(true);
        }
        finally
        {
            IsBusy = false;
        }
    }

    public async Task ScheduleAsync()
    {
        if (IsBusy)
            return;

        IsBusy = true;
        ClearMessages();
        try
        {
            var scanType = FullScan ? DefenderScanType.Full : DefenderScanType.Quick;
            var result = await _scheduler.ScheduleDailyScanAsync(scanType, (int)SelectedHour);
            if (result.Success)
                StatusMessage = result.Message;
            else
                ErrorMessage = result.Message;

            await RefreshInfoOnlyAsync().ConfigureAwait(true);
        }
        finally
        {
            IsBusy = false;
        }
    }

    public async Task RemoveAsync()
    {
        if (IsBusy)
            return;

        IsBusy = true;
        ClearMessages();
        try
        {
            var result = await _scheduler.RemoveScheduledScanAsync();
            if (result.Success)
                StatusMessage = result.Message;
            else
                ErrorMessage = result.Message;

            await RefreshInfoOnlyAsync().ConfigureAwait(true);
        }
        finally
        {
            IsBusy = false;
        }
    }

    private async Task RefreshStatusAsync()
    {
        var result = await _scheduler.GetStatusAsync();
        if (result.Success && result.Value is not null)
        {
            Info = result.Value;
            StatusMessage = result.Message;
        }
        else
        {
            ErrorMessage = result.Message;
        }

        OnPropertyChanged(nameof(Summary));
    }

    /// <summary>Re-reads just the task state (without touching Status/Error messages the
    /// caller already set from a schedule/remove action) so the page reflects Task
    /// Scheduler's real state after a change.</summary>
    private async Task RefreshInfoOnlyAsync()
    {
        var result = await _scheduler.GetStatusAsync();
        if (result.Success && result.Value is not null)
            Info = result.Value;

        OnPropertyChanged(nameof(Summary));
    }
}
