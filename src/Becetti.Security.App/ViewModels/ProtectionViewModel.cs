using Becetti.Security.App.Services;
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
    private readonly SoundService _sound;

    private string _statusText = "Unknown";
    private string _signatureText = "Unknown";
    private string _cloudProtectionText = "Unknown";
    private string _sampleSubmissionText = "Unknown";
    private string _behaviorMonitorText = "Unknown";
    private string _networkProtectionText = "Unknown";
    private bool _realTimeEnabled;
    private bool _isAdministrator;

    public ProtectionViewModel(IDefenderService defender, IEventLogService events, SoundService sound)
    {
        _defender = defender;
        _events = events;
        _sound = sound;
        RefreshCommand = new RelayCommand(LoadAsync);
        EnableRealTimeCommand = new RelayCommand(() => SetRealTimeAsync(true));
        DisableRealTimeCommand = new RelayCommand(() => SetRealTimeAsync(false));
        UpdateSignaturesCommand = new RelayCommand(UpdateSignaturesAsync);
        RestartElevatedCommand = new RelayCommand(RestartElevated);
        OpenWindowsSecurityCommand = new RelayCommand(OpenWindowsSecurity);
    }

    public RelayCommand RefreshCommand { get; }
    public RelayCommand EnableRealTimeCommand { get; }
    public RelayCommand DisableRealTimeCommand { get; }
    public RelayCommand UpdateSignaturesCommand { get; }
    public RelayCommand RestartElevatedCommand { get; }
    /// <summary>Opens Windows Security for settings BECETTI SECURITY does not manage directly.</summary>
    public RelayCommand OpenWindowsSecurityCommand { get; }

    public string StatusText { get => _statusText; set => SetProperty(ref _statusText, value); }
    public string SignatureText { get => _signatureText; set => SetProperty(ref _signatureText, value); }
    public string CloudProtectionText { get => _cloudProtectionText; set => SetProperty(ref _cloudProtectionText, value); }
    public string SampleSubmissionText { get => _sampleSubmissionText; set => SetProperty(ref _sampleSubmissionText, value); }
    public string BehaviorMonitorText { get => _behaviorMonitorText; set => SetProperty(ref _behaviorMonitorText, value); }
    public string NetworkProtectionText { get => _networkProtectionText; set => SetProperty(ref _networkProtectionText, value); }
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
                CloudProtectionText = $"Cloud-delivered protection: {s.CloudProtectionLevel}";
                SampleSubmissionText = $"Automatic sample submission: {s.SampleSubmissionMode}";
                BehaviorMonitorText = s.BehaviorMonitorEnabled ? "Behavior monitoring: On" : "Behavior monitoring: Off";
                NetworkProtectionText = s.NetworkProtectionEnabled ? "Network protection: On" : "Network protection: Off";
            }
            else
            {
                StatusText = "Unknown";
                CloudProtectionText = "Unknown";
                SampleSubmissionText = "Unknown";
                BehaviorMonitorText = "Unknown";
                NetworkProtectionText = "Unknown";
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
                _sound.Play(SoundCue.Warning);
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
                _sound.Play(SoundCue.UpdateCompleted);
            }
            else
            {
                ErrorMessage = result.Message;
                await _events.RecordAsync("signatures.failed", result.Message, false);
                _sound.Play(SoundCue.Warning);
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

    /// <summary>
    /// Opens the real Windows Security app for settings BECETTI SECURITY cannot safely
    /// change itself (e.g. detailed exclusions, ransomware protection folders). Uses the
    /// official windowsdefender: URI scheme — never a custom or simulated settings screen.
    /// </summary>
    private Task OpenWindowsSecurity()
    {
        try
        {
            if (OperatingSystem.IsWindows())
            {
                var startInfo = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "windowsdefender:",
                    UseShellExecute = true
                };
                System.Diagnostics.Process.Start(startInfo);
                StatusMessage = "Opening Windows Security…";
            }
            else
            {
                ErrorMessage = "Windows Security can only be opened on Windows.";
            }
        }
        catch (Exception ex)
        {
            ErrorMessage = $"Could not open Windows Security: {ex.Message}";
        }

        return Task.CompletedTask;
    }
}
