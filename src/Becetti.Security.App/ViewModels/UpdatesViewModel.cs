using Becetti.Security.App.Services;
using Becetti.Security.Core.Models;
using Becetti.Security.Core.Services;

namespace Becetti.Security.App.ViewModels;

/// <summary>
/// Updates page. Application updates (cloud release channel / Microsoft Store)
/// are shown separately from Defender security-intelligence updates.
/// </summary>
public sealed class UpdatesViewModel : ViewModelBase
{
    private const string CurrentAppVersion = "1.0.0";

    private readonly ICloudService _cloud;
    private readonly IDefenderService _defender;
    private readonly IEventLogService _events;
    private readonly SoundService _sound;

    private string _appUpdateText = "Not checked yet.";
    private string _signatureText = "Unknown";
    private string _storeText = "Microsoft Store updates are managed by the Store app. BECETTI SECURITY does not install its own updates.";

    public UpdatesViewModel(ICloudService cloud, IDefenderService defender, IEventLogService events, SoundService sound)
    {
        _cloud = cloud;
        _defender = defender;
        _events = events;
        _sound = sound;
        CheckAppUpdatesCommand = new RelayCommand(CheckAppUpdatesAsync);
        UpdateSignaturesCommand = new RelayCommand(UpdateSignaturesAsync);
        RefreshSignaturesCommand = new RelayCommand(LoadSignaturesAsync);
    }

    public RelayCommand CheckAppUpdatesCommand { get; }
    public RelayCommand UpdateSignaturesCommand { get; }
    public RelayCommand RefreshSignaturesCommand { get; }

    public string AppUpdateText { get => _appUpdateText; set => SetProperty(ref _appUpdateText, value); }
    public string SignatureText { get => _signatureText; set => SetProperty(ref _signatureText, value); }
    public string StoreText { get => _storeText; set => SetProperty(ref _storeText, value); }
    public string CurrentVersion => CurrentAppVersion;

    public async Task CheckAppUpdatesAsync()
    {
        if (IsBusy)
            return;

        IsBusy = true;
        ClearMessages();
        try
        {
            var result = await _cloud.CheckUpdatesAsync(CurrentAppVersion);
            if (result.Success && result.Value is not null)
            {
                var u = result.Value;
                AppUpdateText = u.UpdateAvailable
                    ? $"Version {u.LatestVersion} is available (channel: {u.Channel}).\n{u.ReleaseNotes ?? string.Empty}\nGet it from the Microsoft Store: {u.StoreUrl ?? "see Store app"}"
                    : $"You are on the latest published version ({CurrentAppVersion}).";
                await _events.RecordAsync("updates.checked", AppUpdateText, true);
            }
            else
            {
                AppUpdateText = "Update check unavailable.";
                ErrorMessage = result.Message;
            }
        }
        finally
        {
            IsBusy = false;
        }
    }

    public async Task LoadSignaturesAsync()
    {
        // Defensive try/catch kept consistent with every other ViewModel's LoadAsync:
        // this is invoked both from OnNavigatedTo (an async void - an uncaught exception
        // there would crash the app) and from RefreshSignaturesCommand (RelayCommand.Execute
        // only has try/finally, not try/catch). _defender.GetStatusAsync() already wraps its
        // own failures in a non-throwing OperationResult, but this guards against any
        // unexpected exception surfacing from here instead of silently crashing the UI.
        try
        {
            var status = await _defender.GetStatusAsync();
            if (status.Success && status.Value is not null)
            {
                var s = status.Value;
                if (!s.Available)
                {
                    SignatureText = "Microsoft Defender could not be reached on this device.";
                }
                else if (!s.AntivirusEnabled)
                {
                    SignatureText = "Microsoft Defender Antivirus is disabled on this device, so no signature status is tracked here.";
                }
                else
                {
                    var version = s.AntivirusSignatureVersion is not null
                        ? $"Security intelligence: version {s.AntivirusSignatureVersion}, updated {s.AntivirusSignatureLastUpdated?.ToString("g") ?? "unknown"}"
                        : "Security intelligence version unknown";
                    SignatureText = s.ManagedByAnotherAntivirus
                        ? $"{version}\nDefender running mode: {s.RunningMode} (another antivirus product is the active real-time engine on this device)."
                        : version;
                }
            }
            else
            {
                SignatureText = "Unknown";
                ErrorMessage = status.Message;
            }
        }
        catch (Exception ex)
        {
            SignatureText = "Unknown";
            ErrorMessage = $"Could not read Defender signature status: {ex.Message}";
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

            await LoadSignaturesAsync();
        }
        finally
        {
            IsBusy = false;
        }
    }
}
