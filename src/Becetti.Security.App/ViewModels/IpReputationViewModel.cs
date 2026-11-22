using System.Collections.ObjectModel;
using Becetti.Security.App.Services;
using Becetti.Security.Core.Models;
using Becetti.Security.Core.Services;

namespace Becetti.Security.App.ViewModels;

/// <summary>
/// IP Reputation page: an optional second opinion on a single IP address
/// the user chooses to check (e.g. an unfamiliar connection seen in Network
/// Monitor), on top of (never instead of) BECETTI SECURITY's own local
/// protection. Every report shown here comes from a real AbuseIPDB response.
/// </summary>
public sealed class IpReputationViewModel : ViewModelBase
{
    private readonly IIpReputationService _reputation;
    private readonly IIpReputationHistoryService _history;
    private readonly NotificationService _notifications;

    private string _ipInput = string.Empty;
    private IpReputationReport? _currentReport;

    public IpReputationViewModel(IIpReputationService reputation, IIpReputationHistoryService history, NotificationService notifications)
    {
        _reputation = reputation;
        _history = history;
        _notifications = notifications;

        CheckIpCommand = new RelayCommand(CheckIpAsync, () => !IsBusy && !string.IsNullOrWhiteSpace(IpInput));
        RefreshHistoryCommand = new RelayCommand(LoadHistoryAsync);
    }

    public RelayCommand CheckIpCommand { get; }
    public RelayCommand RefreshHistoryCommand { get; }

    public ObservableCollection<IpReputationCheckRecord> History { get; } = new();

    public bool IsConfigured => _reputation.IsConfigured;
    public bool IsNotConfigured => !_reputation.IsConfigured;

    public string IpInput
    {
        get => _ipInput;
        set
        {
            if (SetProperty(ref _ipInput, value))
                CheckIpCommand.RaiseCanExecuteChanged();
        }
    }

    public IpReputationReport? CurrentReport
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
            }
        }
    }

    public bool HasReport => CurrentReport is not null;
    public bool IsClean => CurrentReport?.Verdict == IpReputationVerdict.Clean;
    public bool IsMalicious => CurrentReport?.Verdict == IpReputationVerdict.Malicious;
    public bool IsSuspicious => CurrentReport?.Verdict == IpReputationVerdict.Suspicious;

    public async Task InitializeAsync()
    {
        await LoadHistoryAsync();
    }

    private async Task CheckIpAsync()
    {
        if (IsBusy)
            return;

        IsBusy = true;
        ClearMessages();
        CurrentReport = null;
        try
        {
            var ip = IpInput.Trim();
            var result = await _reputation.CheckIpAsync(ip);
            if (!result.Success || result.Value is null)
            {
                ErrorMessage = result.Message;
                return;
            }

            var report = result.Value;
            CurrentReport = report;
            StatusMessage = report.Message;

            await _history.RecordAsync(new IpReputationCheckRecord
            {
                IpAddress = report.IpAddress,
                AbuseConfidenceScore = report.AbuseConfidenceScore,
                Verdict = report.Verdict
            });
            await LoadHistoryAsync();

            if (report.Verdict == IpReputationVerdict.Malicious)
            {
                await _notifications.NotifyCriticalAsync(
                    "BECETTI SECURITY — malicious IP address",
                    $"AbuseIPDB flagged \"{report.IpAddress}\" as malicious ({report.AbuseConfidenceScore}% confidence).");
            }
        }
        finally
        {
            IsBusy = false;
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
