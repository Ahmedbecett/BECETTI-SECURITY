using Becetti.Security.Core.Models;
using Becetti.Security.Core.Services;

namespace Becetti.Security.App.ViewModels;

/// <summary>Backup Advisor page: real File History and System Restore posture.</summary>
public sealed class BackupAdvisorViewModel : ViewModelBase
{
    private readonly IBackupAdvisorService _backup;

    private BackupStatus _status = new();

    public BackupAdvisorViewModel(IBackupAdvisorService backup)
    {
        _backup = backup;
        RefreshCommand = new RelayCommand(LoadAsync);
    }

    public RelayCommand RefreshCommand { get; }

    public BackupStatus Status { get => _status; set => SetProperty(ref _status, value); }

    public string FileHistorySummary => Status.FileHistoryConfigured switch
    {
        true => "File History: active",
        false => "File History: not active",
        null => "File History: could not be determined"
    };

    public string RestoreSummary => Status.Available
        ? $"System Restore points: {Status.RestorePointCount}" +
          (Status.LatestRestorePoint is { } latest ? $" (latest: {latest:yyyy-MM-dd HH:mm})" : string.Empty)
        : "System Restore: could not be determined";

    public async Task LoadAsync()
    {
        if (IsBusy)
            return;

        IsBusy = true;
        ClearMessages();
        try
        {
            var result = await _backup.GetStatusAsync();
            if (result.Success && result.Value is not null)
            {
                Status = result.Value;
                StatusMessage = result.Message;
            }
            else
            {
                ErrorMessage = result.Message;
            }

            OnPropertyChanged(nameof(FileHistorySummary));
            OnPropertyChanged(nameof(RestoreSummary));
        }
        finally
        {
            IsBusy = false;
        }
    }
}
