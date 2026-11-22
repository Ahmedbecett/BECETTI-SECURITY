using System.Collections.ObjectModel;
using Becetti.Security.App.Services;
using Becetti.Security.Core.Models;
using Becetti.Security.Core.Services;

namespace Becetti.Security.App.ViewModels;

/// <summary>
/// Data Breach Monitor page: an optional second opinion on credential
/// exposure — "has this email or password shown up in a known public data
/// breach?" — on top of (never instead of) BECETTI SECURITY's core local
/// protection. Every result shown here comes from a real upstream response
/// (XposedOrNot for email, HIBP's Pwned Passwords range API for passwords).
/// </summary>
public sealed class DataBreachViewModel : ViewModelBase
{
    private readonly IDataBreachService _breach;
    private readonly IDataBreachHistoryService _history;
    private readonly NotificationService _notifications;

    private string _emailInput = string.Empty;
    private string _passwordInput = string.Empty;
    private EmailBreachReport? _emailReport;
    private PasswordBreachReport? _passwordReport;

    public DataBreachViewModel(IDataBreachService breach, IDataBreachHistoryService history, NotificationService notifications)
    {
        _breach = breach;
        _history = history;
        _notifications = notifications;

        CheckEmailCommand = new RelayCommand(CheckEmailAsync, () => !IsBusy && !string.IsNullOrWhiteSpace(EmailInput));
        CheckPasswordCommand = new RelayCommand(CheckPasswordAsync, () => !IsBusy && !string.IsNullOrEmpty(PasswordInput));
        RefreshHistoryCommand = new RelayCommand(LoadHistoryAsync);
    }

    public RelayCommand CheckEmailCommand { get; }
    public RelayCommand CheckPasswordCommand { get; }
    public RelayCommand RefreshHistoryCommand { get; }

    public ObservableCollection<DataBreachRecord> EmailBreaches { get; } = new();
    public ObservableCollection<DataBreachCheckRecord> History { get; } = new();

    public bool IsConfigured => _breach.IsConfigured;
    public bool IsNotConfigured => !_breach.IsConfigured;

    public string EmailInput
    {
        get => _emailInput;
        set
        {
            if (SetProperty(ref _emailInput, value))
                CheckEmailCommand.RaiseCanExecuteChanged();
        }
    }

    /// <summary>Bound from the PasswordBox's code-behind PasswordChanged handler — never shown in plain XAML binding.</summary>
    public string PasswordInput
    {
        get => _passwordInput;
        set
        {
            if (SetProperty(ref _passwordInput, value))
                CheckPasswordCommand.RaiseCanExecuteChanged();
        }
    }

    public EmailBreachReport? EmailReport
    {
        get => _emailReport;
        private set
        {
            if (SetProperty(ref _emailReport, value))
            {
                OnPropertyChanged(nameof(HasEmailReport));
                OnPropertyChanged(nameof(EmailIsClean));
                OnPropertyChanged(nameof(EmailIsBreached));
            }
        }
    }

    public PasswordBreachReport? PasswordReport
    {
        get => _passwordReport;
        private set
        {
            if (SetProperty(ref _passwordReport, value))
            {
                OnPropertyChanged(nameof(HasPasswordReport));
                OnPropertyChanged(nameof(PasswordIsClean));
                OnPropertyChanged(nameof(PasswordIsBreached));
            }
        }
    }

    public bool HasEmailReport => EmailReport is not null;
    public bool EmailIsClean => EmailReport is not null && !EmailReport.Breached;
    public bool EmailIsBreached => EmailReport?.Breached == true;

    public bool HasPasswordReport => PasswordReport is not null;
    public bool PasswordIsClean => PasswordReport is not null && !PasswordReport.Breached;
    public bool PasswordIsBreached => PasswordReport?.Breached == true;

    public async Task InitializeAsync()
    {
        await LoadHistoryAsync();
    }

    private async Task CheckEmailAsync()
    {
        if (IsBusy)
            return;

        IsBusy = true;
        ClearMessages();
        EmailReport = null;
        EmailBreaches.Clear();
        try
        {
            var email = EmailInput.Trim();
            var result = await _breach.CheckEmailAsync(email);
            if (!result.Success || result.Value is null)
            {
                ErrorMessage = result.Message;
                return;
            }

            var report = result.Value;
            EmailReport = report;
            StatusMessage = report.Message;

            foreach (var b in report.Breaches)
                EmailBreaches.Add(b);

            await _history.RecordAsync(new DataBreachCheckRecord
            {
                CheckType = DataBreachCheckType.Email,
                TargetDisplay = email,
                Breached = report.Breached,
                Count = report.BreachCount
            });
            await LoadHistoryAsync();

            if (report.Breached)
            {
                await _notifications.NotifyCriticalAsync(
                    "BECETTI SECURITY — data breach found",
                    $"\"{email}\" appeared in {report.BreachCount} known data breach(es).");
            }
        }
        finally
        {
            IsBusy = false;
        }
    }

    private async Task CheckPasswordAsync()
    {
        if (IsBusy)
            return;

        IsBusy = true;
        ClearMessages();
        PasswordReport = null;
        try
        {
            var result = await _breach.CheckPasswordAsync(PasswordInput);
            if (!result.Success || result.Value is null)
            {
                ErrorMessage = result.Message;
                return;
            }

            var report = result.Value;
            PasswordReport = report;
            StatusMessage = report.Message;

            await _history.RecordAsync(new DataBreachCheckRecord
            {
                CheckType = DataBreachCheckType.Password,
                TargetDisplay = "••••••••",
                Breached = report.Breached,
                Count = report.TimesSeen
            });
            await LoadHistoryAsync();

            if (report.Breached)
            {
                await _notifications.NotifyCriticalAsync(
                    "BECETTI SECURITY — exposed password",
                    $"A checked password has appeared in known breaches {report.TimesSeen:N0} time(s).");
            }
        }
        finally
        {
            IsBusy = false;
            // Never keep the checked password around longer than the single
            // request that needed it.
            PasswordInput = string.Empty;
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
