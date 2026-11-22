using Becetti.Security.Core.Models;
using Becetti.Security.Core.Services;

namespace Becetti.Security.App.ViewModels;

/// <summary>
/// Game/Performance Mode page: one real toggle that switches the Windows
/// power plan to High performance and turns on Windows' own Game Mode
/// setting while active, restoring both exactly when turned off.
/// </summary>
public sealed class GamePerformanceModeViewModel : ViewModelBase
{
    private readonly IGamePerformanceModeService _mode;
    private GamePerformanceStatus? _status;

    public GamePerformanceModeViewModel(IGamePerformanceModeService mode)
    {
        _mode = mode;
        ToggleCommand = new RelayCommand(ToggleAsync, () => !IsBusy);
        RefreshCommand = new RelayCommand(LoadAsync);
    }

    public RelayCommand ToggleCommand { get; }
    public RelayCommand RefreshCommand { get; }

    public GamePerformanceStatus? Status
    {
        get => _status;
        private set
        {
            if (SetProperty(ref _status, value))
            {
                OnPropertyChanged(nameof(IsActive));
                OnPropertyChanged(nameof(ToggleButtonLabel));
            }
        }
    }

    public bool IsActive => Status?.Active == true;

    public string ToggleButtonLabel => IsActive ? "Turn off" : "Turn on";

    public async Task InitializeAsync() => await LoadAsync();

    private async Task ToggleAsync()
    {
        if (IsBusy)
            return;

        IsBusy = true;
        ClearMessages();
        try
        {
            var result = IsActive ? await _mode.DisableAsync() : await _mode.EnableAsync();
            if (!result.Success)
            {
                ErrorMessage = result.Message;
                return;
            }

            StatusMessage = result.Message;
            await LoadAsync();
        }
        finally
        {
            IsBusy = false;
        }
    }

    private async Task LoadAsync()
    {
        var result = await _mode.GetStatusAsync();
        if (result.Success && result.Value is not null)
        {
            Status = result.Value;
        }
        else
        {
            ErrorMessage = result.Message;
        }
    }
}
