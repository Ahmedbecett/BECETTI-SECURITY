using System.Collections.ObjectModel;
using Becetti.Security.Core.Models;
using Becetti.Security.Core.Services;

namespace Becetti.Security.App.ViewModels;

/// <summary>
/// Threat Intelligence page: an optional second opinion from VirusTotal's
/// ~70 third-party engines for a file or URL the user chooses, on top of
/// (never instead of) Microsoft Defender, BECETTI SECURITY's own protection
/// engine. Every report shown here comes from a real VirusTotal response.
/// </summary>
public sealed class ThreatIntelligenceViewModel : ViewModelBase
{
    private readonly IThreatIntelligenceService _threatIntel;
    private readonly IThreatIntelHistoryService _history;

    private string _selectedFilePath = string.Empty;
    private string _urlInput = string.Empty;
    private ThreatIntelReport? _currentReport;
    private bool _needsUploadConsent;
    private bool _isPolling;
    private string? _pendingAnalysisId;
    private ThreatIntelTargetType _pendingTargetType;

    public ThreatIntelligenceViewModel(IThreatIntelligenceService threatIntel, IThreatIntelHistoryService history)
    {
        _threatIntel = threatIntel;
        _history = history;

        ScanFileCommand = new RelayCommand(ScanFileAsync, () => !IsBusy && !string.IsNullOrWhiteSpace(SelectedFilePath));
        ConfirmUploadCommand = new RelayCommand(ConfirmUploadAsync, () => !IsBusy && NeedsUploadConsent);
        ScanUrlCommand = new RelayCommand(ScanUrlAsync, () => !IsBusy && !string.IsNullOrWhiteSpace(UrlInput));
        CheckStatusCommand = new RelayCommand(CheckStatusAsync, () => !IsBusy && _pendingAnalysisId is not null);
        RefreshHistoryCommand = new RelayCommand(LoadHistoryAsync);
    }

    public RelayCommand ScanFileCommand { get; }
    public RelayCommand ConfirmUploadCommand { get; }
    public RelayCommand ScanUrlCommand { get; }
    public RelayCommand CheckStatusCommand { get; }
    public RelayCommand RefreshHistoryCommand { get; }

    public ObservableCollection<ThreatIntelEngineVerdict> FlaggedEngines { get; } = new();
    public ObservableCollection<ThreatIntelScanRecord> History { get; } = new();

    public bool IsConfigured => _threatIntel.IsConfigured;
    public bool IsNotConfigured => !_threatIntel.IsConfigured;

    public string SelectedFilePath
    {
        get => _selectedFilePath;
        set
        {
            if (SetProperty(ref _selectedFilePath, value))
                ScanFileCommand.RaiseCanExecuteChanged();
        }
    }

    public string UrlInput
    {
        get => _urlInput;
        set
        {
            if (SetProperty(ref _urlInput, value))
                ScanUrlCommand.RaiseCanExecuteChanged();
        }
    }

    public ThreatIntelReport? CurrentReport
    {
        get => _currentReport;
        private set
        {
            if (SetProperty(ref _currentReport, value))
            {
                OnPropertyChanged(nameof(HasReport));
                OnPropertyChanged(nameof(IsClean));
                OnPropertyChanged(nameof(IsMalicious));
                OnPropertyChanged(nameof(IsSuspicious));
                OnPropertyChanged(nameof(IsQueued));
            }
        }
    }

    public bool NeedsUploadConsent
    {
        get => _needsUploadConsent;
        private set
        {
            if (SetProperty(ref _needsUploadConsent, value))
                ConfirmUploadCommand.RaiseCanExecuteChanged();
        }
    }

    public bool HasReport => CurrentReport is not null;
    public bool IsClean => CurrentReport?.Verdict == ThreatIntelVerdict.Clean;
    public bool IsMalicious => CurrentReport?.Verdict == ThreatIntelVerdict.Malicious;
    public bool IsSuspicious => CurrentReport?.Verdict == ThreatIntelVerdict.Suspicious;
    public bool IsQueued => CurrentReport?.Status == ThreatIntelStatus.Queued;

    /// <summary>Size limit shown in the upload-consent warning, kept in sync with the service's real cap.</summary>
    public string MaxUploadSizeLabel => $"{_threatIntel.MaxUploadBytes / (1024 * 1024)} MB";

    public async Task InitializeAsync()
    {
        await LoadHistoryAsync();
    }

    private async Task ScanFileAsync()
    {
        if (IsBusy)
            return;

        IsBusy = true;
        ClearMessages();
        NeedsUploadConsent = false;
        CurrentReport = null;
        FlaggedEngines.Clear();
        try
        {
            var result = await _threatIntel.ScanFileAsync(SelectedFilePath, allowUpload: false);
            await HandleResultAsync(result, ThreatIntelTargetType.File, SelectedFilePath);

            if (result.Success && result.Value?.Status == ThreatIntelStatus.NotFound)
                NeedsUploadConsent = true;
        }
        finally
        {
            IsBusy = false;
        }
    }

    private async Task ConfirmUploadAsync()
    {
        if (IsBusy || string.IsNullOrWhiteSpace(SelectedFilePath))
            return;

        IsBusy = true;
        ClearMessages();
        NeedsUploadConsent = false;
        try
        {
            var result = await _threatIntel.ScanFileAsync(SelectedFilePath, allowUpload: true);
            await HandleResultAsync(result, ThreatIntelTargetType.File, SelectedFilePath);

            if (result.Success && result.Value?.Status == ThreatIntelStatus.Queued)
                await PollUntilDoneAsync(result.Value.AnalysisId, ThreatIntelTargetType.File, SelectedFilePath);
        }
        finally
        {
            IsBusy = false;
        }
    }

    private async Task ScanUrlAsync()
    {
        if (IsBusy)
            return;

        IsBusy = true;
        ClearMessages();
        NeedsUploadConsent = false;
        CurrentReport = null;
        FlaggedEngines.Clear();
        try
        {
            var result = await _threatIntel.SubmitUrlAsync(UrlInput.Trim());
            await HandleResultAsync(result, ThreatIntelTargetType.Url, UrlInput.Trim());

            if (result.Success && result.Value?.Status == ThreatIntelStatus.Queued)
                await PollUntilDoneAsync(result.Value.AnalysisId, ThreatIntelTargetType.Url, UrlInput.Trim());
        }
        finally
        {
            IsBusy = false;
        }
    }

    private async Task CheckStatusAsync()
    {
        if (IsBusy || _pendingAnalysisId is null)
            return;

        IsBusy = true;
        try
        {
            var target = _pendingTargetType == ThreatIntelTargetType.File ? SelectedFilePath : UrlInput.Trim();
            var result = await _threatIntel.GetAnalysisAsync(_pendingAnalysisId, _pendingTargetType);
            await HandleResultAsync(result, _pendingTargetType, target);
        }
        finally
        {
            IsBusy = false;
        }
    }

    /// <summary>
    /// Polls a real, in-progress VirusTotal analysis a handful of times with
    /// increasing delays. If it is still not done afterward, the user can
    /// keep checking manually via CheckStatusCommand — nothing is faked as
    /// "completed" just because polling stopped.
    /// </summary>
    private async Task PollUntilDoneAsync(string? analysisId, ThreatIntelTargetType targetType, string targetDisplay)
    {
        if (string.IsNullOrWhiteSpace(analysisId) || _isPolling)
            return;

        _isPolling = true;
        try
        {
            int[] delaysSeconds = { 2, 3, 4, 5, 6 };
            foreach (var delay in delaysSeconds)
            {
                await Task.Delay(TimeSpan.FromSeconds(delay));
                var result = await _threatIntel.GetAnalysisAsync(analysisId, targetType);
                await HandleResultAsync(result, targetType, targetDisplay);

                if (!result.Success || result.Value?.Status == ThreatIntelStatus.Completed)
                    return;
            }

            StatusMessage = "VirusTotal is still scanning. Press \"Check status\" to keep checking.";
        }
        finally
        {
            _isPolling = false;
        }
    }

    private async Task HandleResultAsync(OperationResult<ThreatIntelReport> result, ThreatIntelTargetType targetType, string targetDisplay)
    {
        if (!result.Success || result.Value is null)
        {
            ErrorMessage = result.Message;
            _pendingAnalysisId = null;
            CheckStatusCommand.RaiseCanExecuteChanged();
            return;
        }

        var report = result.Value;
        CurrentReport = report;
        StatusMessage = report.Message;

        FlaggedEngines.Clear();
        foreach (var engine in report.FlaggedEngines)
            FlaggedEngines.Add(engine);

        if (report.Status == ThreatIntelStatus.Queued && !string.IsNullOrWhiteSpace(report.AnalysisId))
        {
            _pendingAnalysisId = report.AnalysisId;
            _pendingTargetType = targetType;
        }
        else
        {
            _pendingAnalysisId = null;
        }
        CheckStatusCommand.RaiseCanExecuteChanged();

        if (report.Status == ThreatIntelStatus.Completed)
        {
            await _history.RecordAsync(new ThreatIntelScanRecord
            {
                TargetType = targetType,
                TargetDisplay = targetDisplay,
                Sha256 = report.Sha256,
                Verdict = report.Verdict,
                DetectionRatio = report.DetectionRatio,
                Permalink = report.Permalink
            });
            await LoadHistoryAsync();
        }
    }

    private async Task LoadHistoryAsync()
    {
        var items = await _history.ReadRecentAsync(100);
        History.Clear();
        foreach (var item in items)
            History.Add(item);
    }
}
