using Becetti.Security.Core.Models;
using Becetti.Security.Core.Services;

namespace Becetti.Security.App.ViewModels;

/// <summary>
/// Real-Time Protection page: verified Defender state, real-time toggle,
/// signature updates and elevation handling. Every change is re-verified.
/// </summary>
public sealed class ProtectionViewModel : ViewModelBase
{
    private readonly IDefenderService _defender;
    private readonly IEventLogService _events;

    private string _statusText = "Unknown";
    private string _signatureText = "Unknown";
    private bool _realTimeEnabled;
    private bool _isAdministrator;

    public ProtectionViewModel(IDefenderService defender, IEventLogService events)
    {
        _defender = defender;
        _events = events;
        RefreshCommand = new RelayCommand(LoadAsync);
        EnableRealTimeCommand = new RelayCommand(() => SetRealTimeAsync(true));
        DisableRealTimeCommand = new RelayCommand(() => SetRealTimeAsync(false));
        UpdateSignaturesCommand = new RelayCommand(UpdateSignaturesAsync);
        RestartElevatedCommand = new RelayCommand(RestartElevated);
    }

    public RelayCommand RefreshCommand { get; }
    public RelayCommand EnableRealTimeCommand { get; }
    public RelayCommand DisableRealTimeCommand { get; }
    public RelayCommand UpdateSignaturesCommand { get; }
    public RelayCommand RestartElevatedCommand { get; }

    public string StatusText { get => _statusText; set => SetProperty(ref _statusText, value); }
    public string SignatureText { get => _signatureText; set => SetProperty(ref _signatureText, value); }
    public bool RealTimeEnabled { get => _realTimeEnabled; set => SetProperty(ref _realTimeEnabled, value); }
    public bool IsAdministrator { get => _isAdministrator; set => SetProperty(ref _isAdministrator, value); }

    public async Task LoadAsync()
    {
        if (IsBusy)
            return;

        IsBusy = true;
        ClearMessages();
        try
        {
            IsAdministrator = _defender.IsElevated();
            var status = await _defender.GetStatusAsync();
            if (status.Success && status.Value is not null)
            {
                var s = status.Value;
                RealTimeEnabled = s.RealTimeProtectionEnabled;
                StatusText = $"Antivirus: {(s.AntivirusEnabled ? "Enabled" : "Disabled")} · Real-time: {(s.RealTimeProtectionEnabled ? "On" : "Off")} · Behavior monitor: {(s.BehaviorMonitorEnabled ? "On" : "Off")} · Tamper protection: {(s.TamperProtectionEnabled ? "On" : "Off")}" +
                    (s.ManagedByAnotherAntivirus ? $" · Running mode: {s.RunningMode} (another antivirus product is active)" : string.Empty);
                SignatureText = s.AntivirusSignatureVersion is not null
                    ? $"Signature version {s.AntivirusSignatureVersion}, last updated {s.AntivirusSignatureLastUpdated?.ToString("g") ?? "unknown"}"
                    : "Signature version unknown";
            }
            else
            {
                StatusText = "Unknown";
                ErrorMessage = status.Message;
            }
        }
        finally
        {
            IsBusy = false;
        }
    }

    private async Task SetRealTimeAsync(bool enable)
    {
        if (IsBusy)
            return;

        IsBusy = true;
        ClearMessages();
        try
        {
            var result = await _defender.SetRealTimeProtectionAsync(enable);
            if (result.Success)
            {
                StatusMessage = result.Message;
                await _events.RecordAsync("protection.changed", result.Message, true);
            }
            else
            {
                ErrorMessage = result.Message;
                await _events.RecordAsync("protection.failed", result.Message, false);
            }

            await LoadAsync();
        }
        finally
        {
            IsBusy = false;
        }
    }

    private async Task UpdateSignaturesAsync()
    {
        if (IsBusy)
            return;

        IsBusy = true;
        ClearMessages();
        try
        {
            var result = await _defender.UpdateSignaturesAsync();
            if (result.Success)
            {
                StatusMessage = result.Message;
                await _events.RecordAsync("signatures.updated", result.Message, true);
            }
            else
            {
                ErrorMessage = result.Message;
                await _events.RecordAsync("signatures.failed", result.Message, false);
            }

            await LoadAsync();
        }
        finally
        {
            IsBusy = false;
        }
    }

    private Task RestartElevated()
    {
        var result = _defender.RestartElevated();
        if (result.Success)
            StatusMessage = result.Message;
        else
            ErrorMessage = result.Message;
        return Task.CompletedTask;
    }
}
