using System.Collections.ObjectModel;
using Becetti.Security.Core.Models;
using Becetti.Security.Core.Services;

namespace Becetti.Security.App.ViewModels;

/// <summary>
/// Cloud Security page: API connection test, sign-in, file-reputation
/// checks, and the multi-device dashboard (every real device that has
/// checked in under the signed-in account). Only the file's SHA-256 hash is
/// sent for reputation checks — never the file itself.
/// </summary>
public sealed class CloudViewModel : ViewModelBase
{
    private const string AppVersion = "1.0.0";

    private readonly ICloudService _cloud;
    private readonly ISettingsService _settings;
    private readonly IEventLogService _events;

    private string _apiUrl = string.Empty;
    private string _email = string.Empty;
    private string _password = string.Empty;
    private string _connectionText = "Not configured";
    private string _accountText = "Not signed in";
    private string _reputationFilePath = string.Empty;
    private string _reputationText = "No reputation check run yet.";
    private bool _isSignedIn;
    private string _devicesStatusText = "Sign in to see devices on this account.";

    public CloudViewModel(ICloudService cloud, ISettingsService settings, IEventLogService events)
    {
        _cloud = cloud;
        _settings = settings;
        _events = events;
        ApiUrl = settings.Current.ApiBaseUrl;
        TestConnectionCommand = new RelayCommand(TestConnectionAsync);
        SaveApiUrlCommand = new RelayCommand(SaveApiUrlAsync);
        LoginCommand = new RelayCommand(LoginAsync);
        RegisterCommand = new RelayCommand(RegisterAsync);
        LogoutCommand = new RelayCommand(LogoutAsync);
        CheckReputationCommand = new RelayCommand(CheckReputationAsync);
        RefreshAccountCommand = new RelayCommand(RefreshAccountAsync);
        RefreshDevicesCommand = new RelayCommand(RefreshDevicesAsync, () => !IsBusy);
    }

    public RelayCommand TestConnectionCommand { get; }
    public RelayCommand SaveApiUrlCommand { get; }
    public RelayCommand LoginCommand { get; }
    public RelayCommand RegisterCommand { get; }
    public RelayCommand LogoutCommand { get; }
    public RelayCommand CheckReputationCommand { get; }
    public RelayCommand RefreshAccountCommand { get; }
    public RelayCommand RefreshDevicesCommand { get; }

    public ObservableCollection<DeviceSummary> Devices { get; } = new();
    public bool HasDevices => Devices.Count > 0;
    public string DevicesStatusText { get => _devicesStatusText; set => SetProperty(ref _devicesStatusText, value); }

    public string ApiUrl { get => _apiUrl; set => SetProperty(ref _apiUrl, value); }
    public string Email { get => _email; set => SetProperty(ref _email, value); }
    public string Password { get => _password; set => SetProperty(ref _password, value); }
    public string ConnectionText { get => _connectionText; set => SetProperty(ref _connectionText, value); }
    public string AccountText { get => _accountText; set => SetProperty(ref _accountText, value); }
    public string ReputationFilePath { get => _reputationFilePath; set => SetProperty(ref _reputationFilePath, value); }
    public string ReputationText { get => _reputationText; set => SetProperty(ref _reputationText, value); }
    public bool IsSignedIn { get => _isSignedIn; set => SetProperty(ref _isSignedIn, value); }

    public async Task SaveApiUrlAsync()
    {
        if (IsBusy)
            return;

        IsBusy = true;
        try
        {
            _settings.Current.ApiBaseUrl = ApiUrl.Trim();
            await _settings.SaveAsync();
            StatusMessage = "API URL saved. Test the connection to verify it.";
            await TestConnectionAsync();
        }
        finally
        {
            IsBusy = false;
        }
    }

    public async Task TestConnectionAsync()
    {
        if (IsBusy)
            return;

        IsBusy = true;
        ClearMessages();
        try
        {
            var health = await _cloud.GetHealthAsync();
            if (health.Success && health.Value is not null)
            {
                ConnectionText = $"Connected — API {health.Value.Version}, server time {health.Value.ServerTime:u}";
                StatusMessage = "Cloud API is reachable.";
            }
            else
            {
                ConnectionText = "Not connected";
                ErrorMessage = health.Message;
            }

            await RefreshAccountAsync();
        }
        finally
        {
            IsBusy = false;
        }
    }

    public async Task LoginAsync()
    {
        if (IsBusy)
            return;

        IsBusy = true;
        ClearMessages();
        try
        {
            var result = await _cloud.LoginAsync(Email.Trim(), Password);
            if (result.Success)
            {
                StatusMessage = result.Message;
                await _events.RecordAsync("cloud.login", "Signed in to cloud API", true);
            }
            else
            {
                ErrorMessage = result.Message;
                await _events.RecordAsync("cloud.login.failed", result.Message, false);
            }

            await RefreshAccountAsync();
        }
        finally
        {
            IsBusy = false;
        }
    }

    public async Task RegisterAsync()
    {
        if (IsBusy)
            return;

        IsBusy = true;
        ClearMessages();
        try
        {
            var result = await _cloud.RegisterAsync(Email.Trim(), Password);
            if (result.Success)
            {
                StatusMessage = result.Message;
                await _events.RecordAsync("cloud.register", "Created cloud account", true);
            }
            else
            {
                ErrorMessage = result.Message;
                await _events.RecordAsync("cloud.register.failed", result.Message, false);
            }

            await RefreshAccountAsync();
        }
        finally
        {
            IsBusy = false;
        }
    }

    public async Task LogoutAsync()
    {
        if (IsBusy)
            return;

        IsBusy = true;
        ClearMessages();
        try
        {
            var result = await _cloud.LogoutAsync();
            StatusMessage = result.Message;
            await RefreshAccountAsync();
        }
        finally
        {
            IsBusy = false;
        }
    }

    public async Task RefreshAccountAsync()
    {
        // Try/catch kept consistent with every other command method in this ViewModel:
        // RelayCommand.Execute only has try/finally, not try/catch, so an uncaught
        // exception here would otherwise surface as an unhandled exception on the UI
        // thread instead of a normal ErrorMessage.
        try
        {
            IsSignedIn = _cloud.IsAuthenticated;
            if (!_cloud.IsAuthenticated)
            {
                AccountText = "Not signed in";
                return;
            }

            var me = await _cloud.GetCurrentUserEmailAsync();
            AccountText = me.Success ? $"Signed in as {me.Value}" : "Session present, account details unavailable";

            await RefreshDevicesAsync();
        }
        catch (Exception ex)
        {
            AccountText = "Account details unavailable";
            ErrorMessage = $"Could not refresh account details: {ex.Message}";
        }
    }

    public async Task InitializeAsync()
    {
        await RefreshAccountAsync();
    }

    /// <summary>
    /// Sends a real heartbeat for this installation (so it shows up on the
    /// dashboard) and then refreshes the real device list from the server.
    /// </summary>
    public async Task RefreshDevicesAsync()
    {
        if (!_cloud.IsAuthenticated)
        {
            Devices.Clear();
            OnPropertyChanged(nameof(HasDevices));
            DevicesStatusText = "Sign in to see devices on this account.";
            RefreshDevicesCommand.RaiseCanExecuteChanged();
            return;
        }

        try
        {
            var heartbeat = await _cloud.SendDeviceHeartbeatAsync(Environment.MachineName, "Windows", AppVersion);
            if (!heartbeat.Success)
                DevicesStatusText = $"Could not update this device's check-in: {heartbeat.Message}";

            var devices = await _cloud.GetDevicesAsync();
            if (devices.Success && devices.Value is not null)
            {
                Devices.Clear();
                foreach (var device in devices.Value)
                    Devices.Add(device);

                DevicesStatusText = Devices.Count switch
                {
                    0 => "No devices have checked in yet.",
                    1 => "1 device on this account.",
                    _ => $"{Devices.Count} devices on this account."
                };
            }
            else if (heartbeat.Success)
            {
                DevicesStatusText = $"Could not load devices: {devices.Message}";
            }
        }
        catch (Exception ex)
        {
            DevicesStatusText = $"Could not load devices: {ex.Message}";
        }
        finally
        {
            OnPropertyChanged(nameof(HasDevices));
            RefreshDevicesCommand.RaiseCanExecuteChanged();
        }
    }

    /// <summary>Removes a device from the dashboard. Called from the page's code-behind with the clicked row's DeviceSummary.</summary>
    public async Task RemoveDeviceAsync(DeviceSummary device)
    {
        if (IsBusy)
            return;

        IsBusy = true;
        ClearMessages();
        try
        {
            var result = await _cloud.RemoveDeviceAsync(device.DeviceId);
            if (result.Success)
            {
                StatusMessage = $"Removed {device.DeviceName} from this account.";
                await _events.RecordAsync("cloud.device.remove", $"Removed device {device.DeviceName}", true);
                await RefreshDevicesAsync();
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
    }

    public async Task CheckReputationAsync()
    {
        if (IsBusy)
            return;

        if (string.IsNullOrWhiteSpace(ReputationFilePath) || !File.Exists(ReputationFilePath))
        {
            ErrorMessage = "Choose an existing file to check.";
            return;
        }

        IsBusy = true;
        ClearMessages();
        try
        {
            ReputationText = "Hashing file locally...";
            var sha256 = await FileHashService.ComputeSha256Async(ReputationFilePath);
            ReputationText = $"SHA-256: {sha256}\nAsking cloud API...";

            var result = await _cloud.CheckReputationAsync(sha256);
            if (result.Success && result.Value is not null)
            {
                var v = result.Value;
                ReputationText = $"Verdict: {v.Verdict}\nSource: {v.Source}\nDetail: {v.Detail ?? "—"}\nChecked: {v.CheckedAt:u}";
                await _events.RecordAsync("cloud.reputation", $"Reputation check: {v.Verdict} ({v.Source})", true, sha256);
            }
            else
            {
                ReputationText = "Reputation check failed.";
                ErrorMessage = result.Message;
                await _events.RecordAsync("cloud.reputation.failed", result.Message, false, sha256);
            }
        }
        catch (Exception ex)
        {
            ErrorMessage = $"Could not hash the file: {ex.Message}";
        }
        finally
        {
            IsBusy = false;
        }
    }
}
