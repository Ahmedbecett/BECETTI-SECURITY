using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Windows.Input;
using Becetti.Security.App.Services;
using Becetti.Security.Core.Models;
using Becetti.Security.Core.Services;

namespace Becetti.Security.App.ViewModels;

public sealed class GlobalIntelViewModel : ViewModelBase
{
    private readonly IThreatFeedService _feeds;
    private readonly IOutboundRadarService _radar;
    private readonly IWindowsPrivacyHardenerService _privacy;
    private readonly IAppUpdaterService _updater;
    private readonly IEventLogService _events;
    private readonly IAiTriageNavigator _aiTriage;

    private string _feedSummary = string.Empty;
    private string _iocLookupInput = string.Empty;
    private string _iocLookupResult = "Paste any IP address, domain, URL, or SHA-256 hash to check against synced abuse.ch threat feeds.";

    private string _radarSummary = "Click 'Scan Live Outbound Connections' to map active connections by Country/ASN and check against Botnet C2 feeds.";
    private OutboundConnectionIntel? _selectedConnection;

    private string _privacyScoreText = "—";
    private string _privacySummary = "Click 'Audit Windows Privacy' to inspect live Registry telemetry & tracking controls.";

    private string _updaterCurrentVersion = string.Empty;
    private string _updaterSummary = "Click 'Check for Updates' to query official BECETTI SECURITY GitHub Releases.";
    private string _updaterNotes = string.Empty;
    private string _updaterDownloadUrl = string.Empty;
    private bool _hasUpdateDownload;

    public GlobalIntelViewModel(
        IThreatFeedService feeds,
        IOutboundRadarService radar,
        IWindowsPrivacyHardenerService privacy,
        IAppUpdaterService updater,
        IEventLogService events,
        IAiTriageNavigator aiTriage)
    {
        _feeds = feeds;
        _radar = radar;
        _privacy = privacy;
        _updater = updater;
        _events = events;
        _aiTriage = aiTriage;

        _feedSummary = _feeds.GetStatus().Summary;
        _updaterCurrentVersion = $"Installed Version: v{_updater.GetCurrentVersion()}";

        foreach (var tech in MitreAttackMapper.GetAllMappedTechniques())
            MitreTechniques.Add(tech);

        SyncFeedsCommand = new RelayCommand(SyncFeedsAsync, () => !IsBusy);
        LookupIocCommand = new RelayCommand(LookupIocAsync, () => !string.IsNullOrWhiteSpace(IocLookupInput));

        ScanRadarCommand = new RelayCommand(ScanRadarAsync, () => !IsBusy);
        BlockSelectedConnectionCommand = new RelayCommand(BlockSelectedConnectionAsync, () => !IsBusy && SelectedConnection is { CanBlockApp: true });
        AskAiConnectionCommand = new RelayCommand(AskAiConnectionAsync, () => SelectedConnection is not null);

        AuditPrivacyCommand = new RelayCommand(AuditPrivacyAsync, () => !IsBusy);
        HardenAllPrivacyCommand = new RelayCommand(HardenAllPrivacyAsync, () => !IsBusy);

        CheckUpdatesCommand = new RelayCommand(CheckUpdatesAsync, () => !IsBusy);
        DownloadUpdateCommand = new RelayCommand(DownloadUpdateAsync, () => HasUpdateDownload);
    }

    public ObservableCollection<OutboundConnectionIntel> OutboundConnections { get; } = new();
    public ObservableCollection<MitreAttackReference> MitreTechniques { get; } = new();
    public ObservableCollection<PrivacyControlItem> PrivacyControls { get; } = new();

    public string FeedSummary { get => _feedSummary; set => SetProperty(ref _feedSummary, value); }
    public string IocLookupInput
    {
        get => _iocLookupInput;
        set { if (SetProperty(ref _iocLookupInput, value)) NotifyCommands(); }
    }
    public string IocLookupResult { get => _iocLookupResult; set => SetProperty(ref _iocLookupResult, value); }

    public string RadarSummary { get => _radarSummary; set => SetProperty(ref _radarSummary, value); }
    public OutboundConnectionIntel? SelectedConnection
    {
        get => _selectedConnection;
        set { if (SetProperty(ref _selectedConnection, value)) NotifyCommands(); }
    }

    public string PrivacyScoreText { get => _privacyScoreText; set => SetProperty(ref _privacyScoreText, value); }
    public string PrivacySummary { get => _privacySummary; set => SetProperty(ref _privacySummary, value); }

    public string UpdaterCurrentVersion { get => _updaterCurrentVersion; set => SetProperty(ref _updaterCurrentVersion, value); }
    public string UpdaterSummary { get => _updaterSummary; set => SetProperty(ref _updaterSummary, value); }
    public string UpdaterNotes { get => _updaterNotes; set => SetProperty(ref _updaterNotes, value); }
    public bool HasUpdateDownload
    {
        get => _hasUpdateDownload;
        set { if (SetProperty(ref _hasUpdateDownload, value)) NotifyCommands(); }
    }

    public ICommand SyncFeedsCommand { get; }
    public ICommand LookupIocCommand { get; }
    public ICommand ScanRadarCommand { get; }
    public ICommand BlockSelectedConnectionCommand { get; }
    public ICommand AskAiConnectionCommand { get; }
    public ICommand AuditPrivacyCommand { get; }
    public ICommand HardenAllPrivacyCommand { get; }
    public ICommand CheckUpdatesCommand { get; }
    public ICommand DownloadUpdateCommand { get; }

    private void NotifyCommands()
    {
        (SyncFeedsCommand as RelayCommand)?.RaiseCanExecuteChanged();
        (LookupIocCommand as RelayCommand)?.RaiseCanExecuteChanged();
        (ScanRadarCommand as RelayCommand)?.RaiseCanExecuteChanged();
        (BlockSelectedConnectionCommand as RelayCommand)?.RaiseCanExecuteChanged();
        (AskAiConnectionCommand as RelayCommand)?.RaiseCanExecuteChanged();
        (AuditPrivacyCommand as RelayCommand)?.RaiseCanExecuteChanged();
        (HardenAllPrivacyCommand as RelayCommand)?.RaiseCanExecuteChanged();
        (CheckUpdatesCommand as RelayCommand)?.RaiseCanExecuteChanged();
        (DownloadUpdateCommand as RelayCommand)?.RaiseCanExecuteChanged();
    }

    public async Task SyncFeedsAsync()
    {
        ClearMessages();
        IsBusy = true;
        NotifyCommands();
        try
        {
            var res = await _feeds.SyncFeedsAsync();
            if (!res.Success || res.Value is null) { ErrorMessage = res.Message; return; }
            FeedSummary = res.Value.Summary;
            StatusMessage = res.Message;
            await _events.RecordAsync("ThreatFeedSync", res.Message, true);
        }
        finally { IsBusy = false; NotifyCommands(); }
    }

    private Task LookupIocAsync()
    {
        ClearMessages();
        var raw = IocLookupInput.Trim();
        var match = _feeds.CheckIp(raw) ?? _feeds.CheckSha256(raw) ?? _feeds.CheckDomainOrUrl(raw);
        if (match is not null)
        {
            IocLookupResult = $"ALERT — {match.DisplayLine}\nContext: {match.Context}\nMITRE ATT&CK: {match.Mitre.Badge}";
            ErrorMessage = $"Indicator matched global threat feed ({match.FeedSource})!";
        }
        else
        {
            IocLookupResult = $"Clean in local abuse.ch Threat Feeds ({_feeds.GetStatus().TotalIndicators:N0} indicators checked).";
            StatusMessage = "No match in synced global threat feeds.";
        }
        return Task.CompletedTask;
    }

    public async Task ScanRadarAsync()
    {
        ClearMessages();
        IsBusy = true;
        NotifyCommands();
        try
        {
            var res = await _radar.ScanLiveOutboundAsync(resolveGeoIp: true);
            if (!res.Success || res.Value is null) { ErrorMessage = res.Message; return; }
            OutboundConnections.Clear();
            foreach (var c in res.Value.Connections) OutboundConnections.Add(c);
            RadarSummary = res.Message;
            StatusMessage = res.Message;
            await _events.RecordAsync("OutboundRadar", res.Message, res.Value.ThreatFeedMatches == 0);
        }
        finally { IsBusy = false; NotifyCommands(); }
    }

    private async Task BlockSelectedConnectionAsync()
    {
        if (SelectedConnection is null || !SelectedConnection.CanBlockApp) return;
        ClearMessages();
        IsBusy = true;
        NotifyCommands();
        try
        {
            var res = await _radar.BlockProcessExecutableAsync(SelectedConnection.ExecutablePath);
            if (!res.Success) { ErrorMessage = res.Message; return; }
            StatusMessage = res.Message;
            await _events.RecordAsync("FirewallAppBlocked", res.Message, true, SelectedConnection.ExecutablePath);
        }
        finally { IsBusy = false; NotifyCommands(); }
    }

    private Task AskAiConnectionAsync()
    {
        if (SelectedConnection is null) return Task.CompletedTask;
        var c = SelectedConnection;
        var prompt = $"Analyze this live outbound network connection captured by BECETTI SECURITY GeoIP Radar:\n" +
                     $"Process: {c.ProcessName} (PID {c.ProcessId})\nPath: {c.ExecutablePath}\n" +
                     $"Remote: {c.RemoteIp}:{c.RemotePort} ({c.Country} / {c.Organization})\n" +
                     $"Threat Feed Match: {(c.IsThreatFeedMatch ? c.ThreatFeedSource : "None")}\n" +
                     $"Is this connection normal or suspicious, and should I block the app in Windows Firewall?";
        _aiTriage.SendToBecettiAi(prompt);
        return Task.CompletedTask;
    }

    public async Task AuditPrivacyAsync()
    {
        ClearMessages();
        IsBusy = true;
        NotifyCommands();
        try
        {
            var res = await _privacy.AuditPrivacyControlsAsync();
            if (!res.Success || res.Value is null) { ErrorMessage = res.Message; return; }
            PrivacyControls.Clear();
            foreach (var c in res.Value.Controls) PrivacyControls.Add(c);
            PrivacyScoreText = $"{res.Value.PrivacyScorePercent}%";
            PrivacySummary = res.Message;
        }
        finally { IsBusy = false; NotifyCommands(); }
    }

    public async Task TogglePrivacyControlAsync(PrivacyControlItem item)
    {
        if (item is null) return;
        ClearMessages();
        IsBusy = true;
        NotifyCommands();
        try
        {
            var res = await _privacy.SetControlHardenedAsync(item.Id, !item.IsHardened);
            if (!res.Success) { ErrorMessage = res.Message; return; }
            var okMsg = res.Message;
            await _events.RecordAsync("PrivacyHardening", okMsg, true, item.Id);
            await RefreshPrivacyListCoreAsync();
            StatusMessage = okMsg;
        }
        finally { IsBusy = false; NotifyCommands(); }
    }

    private async Task HardenAllPrivacyAsync()
    {
        ClearMessages();
        IsBusy = true;
        NotifyCommands();
        try
        {
            var res = await _privacy.HardenAllRecommendedAsync();
            if (!res.Success) { ErrorMessage = res.Message; return; }
            var okMsg = res.Message;
            await _events.RecordAsync("PrivacyHardeningAll", okMsg, true);
            await RefreshPrivacyListCoreAsync();
            StatusMessage = okMsg;
        }
        finally { IsBusy = false; NotifyCommands(); }
    }

    private async Task RefreshPrivacyListCoreAsync()
    {
        var res = await _privacy.AuditPrivacyControlsAsync();
        if (!res.Success || res.Value is null) { ErrorMessage = res.Message; return; }
        PrivacyControls.Clear();
        foreach (var c in res.Value.Controls) PrivacyControls.Add(c);
        PrivacyScoreText = $"{res.Value.PrivacyScorePercent}%";
        PrivacySummary = res.Message;
    }

    public async Task CheckUpdatesAsync()
    {
        ClearMessages();
        IsBusy = true;
        NotifyCommands();
        try
        {
            var res = await _updater.CheckLatestGitHubReleaseAsync();
            if (!res.Success || res.Value is null) { ErrorMessage = res.Message; return; }
            var info = res.Value;
            UpdaterSummary = res.Message;
            UpdaterNotes = $"Release: {info.LatestTag} (v{info.LatestVersion})\nAsset: {info.MsixFileName}\n\n{info.ReleaseNotes}";
            // Store build: AppUpdaterService deliberately returns no direct MSIX
            // URL (Store policy 10.2.5 - updates come only from the Store), so the
            // only reachable link is the release notes page. Never turn that into a
            // "download the installer" button inside a Store-distributed app.
            var packaged = AppUpdaterService.IsPackagedBuild();
            _updaterDownloadUrl = !string.IsNullOrWhiteSpace(info.MsixDownloadUrl)
                ? info.MsixDownloadUrl
                : (packaged ? string.Empty : info.ReleasePageUrl);
            HasUpdateDownload = !string.IsNullOrWhiteSpace(_updaterDownloadUrl);
            StatusMessage = res.Message;
        }
        finally { IsBusy = false; NotifyCommands(); }
    }

    private Task DownloadUpdateAsync()
    {
        if (Uri.TryCreate(_updaterDownloadUrl, UriKind.Absolute, out var uri) && uri.Scheme == Uri.UriSchemeHttps)
        {
            try
            {
                Process.Start(new ProcessStartInfo { FileName = uri.ToString(), UseShellExecute = true });
                StatusMessage = "Opened official signed MSIX update download in your browser.";
            }
            catch (Exception ex)
            {
                ErrorMessage = $"Could not open update URL: {ex.Message}";
            }
        }
        else if (!string.IsNullOrWhiteSpace(_updaterDownloadUrl))
        {
            ErrorMessage = "Blocked non-HTTPS update URL for security.";
        }
        return Task.CompletedTask;
    }
}
