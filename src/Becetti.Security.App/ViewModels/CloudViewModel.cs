using Becetti.Security.Core.Models;
using Becetti.Security.Core.Services;

namespace Becetti.Security.App.ViewModels;

/// <summary>
/// Cloud Security page: API connection test, sign-in, and file-reputation
/// checks. Only the file's SHA-256 hash is sent — never the file itself.
/// </summary>
public sealed class CloudViewModel : ViewModelBase
{
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
    }

    public RelayCommand TestConnectionCommand { get; }
    public RelayCommand SaveApiUrlCommand { get; }
    public RelayCommand LoginCommand { get; }
    public RelayCommand RegisterCommand { get; }
    public RelayCommand LogoutCommand { get; }
    public RelayCommand CheckReputationCommand { get; }
    public RelayCommand RefreshAccountCommand { get; }

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
        IsSignedIn = _cloud.IsAuthenticated;
        if (!_cloud.IsAuthenticated)
        {
            AccountText = "Not signed in";
            return;
        }

        var me = await _cloud.GetCurrentUserEmailAsync();
        AccountText = me.Success ? $"Signed in as {me.Value}" : "Session present, account details unavailable";
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
