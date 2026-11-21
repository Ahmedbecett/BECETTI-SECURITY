using Becetti.Security.Core.Models;
using Becetti.Security.Core.Services;

namespace Becetti.Security.App.ViewModels;

/// <summary>
/// Ransomware Defense page: reads and explains Microsoft Defender's own
/// Controlled Folder Access feature (Exploit Guard). BECETTI SECURITY does
/// not implement its own ransomware detection — every value here comes from
/// Get-MpPreference, and every toggle goes through the real Set-MpPreference
/// interface, re-verified before success is reported.
/// </summary>
public sealed class RansomwareViewModel : ViewModelBase
{
    private readonly IDefenderService _defender;

    private RansomwareProtectionStatus? _status;
    private bool _isElevated;

    public RansomwareViewModel(IDefenderService defender)
    {
        _defender = defender;
        RefreshCommand = new RelayCommand(LoadAsync);
        EnableCommand = new RelayCommand(() => SetAsync(true));
        DisableCommand = new RelayCommand(() => SetAsync(false));
    }

    public RelayCommand RefreshCommand { get; }
    public RelayCommand EnableCommand { get; }
    public RelayCommand DisableCommand { get; }

    public RansomwareProtectionStatus? Status
    {
        get => _status;
        private set
        {
            if (SetProperty(ref _status, value))
            {
                OnPropertyChanged(nameof(IsEnabled));
                OnPropertyChanged(nameof(StateText));
                OnPropertyChanged(nameof(ProtectedFolders));
                OnPropertyChanged(nameof(AllowedApplications));
                OnPropertyChanged(nameof(HasProtectedFolders));
            }
        }
    }

    public bool IsElevated
    {
        get => _isElevated;
        private set
        {
            if (SetProperty(ref _isElevated, value))
                OnPropertyChanged(nameof(NeedsElevation));
        }
    }

    /// <summary>True when an administrator restart is needed before the toggle can be used.</summary>
    public bool NeedsElevation => !IsElevated;

    public bool IsEnabled => Status?.ControlledFolderAccessEnabled ?? false;
    public string StateText => Status?.ControlledFolderAccessState ?? "Unknown";
    public IReadOnlyList<string> ProtectedFolders => Status?.ProtectedFolders ?? Array.Empty<string>();
    public IReadOnlyList<string> AllowedApplications => Status?.AllowedApplications ?? Array.Empty<string>();
    public bool HasProtectedFolders => ProtectedFolders.Count > 0;

    public async Task LoadAsync()
    {
        if (IsBusy)
            return;

        IsBusy = true;
        ClearMessages();
        try
        {
            IsElevated = _defender.IsElevated();

            var result = await _defender.GetRansomwareProtectionAsync();
            if (result.Success && result.Value is not null)
            {
                Status = result.Value;
                StatusMessage = "Ransomware protection state read from Microsoft Defender.";
            }
            else
            {
                Status = null;
                ErrorMessage = result.Message;
            }
        }
        finally
        {
            IsBusy = false;
        }
    }

    private async Task SetAsync(bool enable)
    {
        if (IsBusy)
            return;

        IsBusy = true;
        ClearMessages();
        try
        {
            var result = await _defender.SetControlledFolderAccessAsync(enable);
            if (result.Success)
            {
                StatusMessage = result.Message;
            }
            else
            {
                ErrorMessage = result.Message;
            }
        }
        finally
        {
            IsBusy = false;
        }

        await LoadAsync();
    }
}
