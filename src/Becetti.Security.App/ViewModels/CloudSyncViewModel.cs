using Becetti.Security.Core.Models;
using Becetti.Security.Core.Services;

namespace Becetti.Security.App.ViewModels;

/// <summary>
/// Cloud Sync page: triggers a real reachability/auth check against the
/// cloud API through ICloudSyncService and shows its verified result.
/// </summary>
public sealed class CloudSyncViewModel : ViewModelBase
{
    private readonly ICloudSyncService _sync;

    private CloudSyncStatus _status = new();

    public CloudSyncViewModel(ICloudSyncService sync)
    {
        _sync = sync;
        SyncNowCommand = new RelayCommand(SyncNowAsync);
    }

    public RelayCommand SyncNowCommand { get; }

    public CloudSyncStatus Status { get => _status; set => SetProperty(ref _status, value); }

    public string StatusSummary => Status switch
    {
        { Configured: false } => "Cloud API is not configured. Set the API URL in Settings.",
        { Reachable: false } => $"Cloud unreachable: {Status.RawError ?? "unknown error"}",
        { Authenticated: true } => $"Connected — signed in as {Status.AccountEmail ?? "(email unavailable)"}",
        _ => "Connected — not signed in"
    };

    public string LastSyncedSummary => Status.LastSyncedAt is { } at
        ? $"Last synced: {at:yyyy-MM-dd HH:mm}"
        : "Never synced in this session.";

    public async Task LoadAsync()
    {
        if (_sync.LastKnownStatus is { } known)
        {
            Status = known;
            RaiseSummaryChanges();
        }

        await SyncNowAsync();
    }

    public async Task SyncNowAsync()
    {
        if (IsBusy)
            return;

        IsBusy = true;
        ClearMessages();
        try
        {
            var result = await _sync.SyncNowAsync();
            if (result.Success && result.Value is not null)
            {
                Status = result.Value;
                StatusMessage = result.Message;
            }
            else
            {
                if (result.Value is not null)
                    Status = result.Value;
                ErrorMessage = result.Message;
            }

            RaiseSummaryChanges();
        }
        finally
        {
            IsBusy = false;
        }
    }

    private void RaiseSummaryChanges()
    {
        OnPropertyChanged(nameof(StatusSummary));
        OnPropertyChanged(nameof(LastSyncedSummary));
    }
}
