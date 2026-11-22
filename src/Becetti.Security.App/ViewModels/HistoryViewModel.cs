using System.Collections.ObjectModel;
using Becetti.Security.Core.Models;
using Becetti.Security.Core.Services;

namespace Becetti.Security.App.ViewModels;

/// <summary>
/// Interactive Security Timeline &amp; 7-Day Activity Chart:
/// real local event log with live severity filtering (All / Alerts / Passed),
/// instant keyword search, and a real 7-day daily activity bar chart. Zero simulation.
/// </summary>
public sealed class HistoryViewModel : ViewModelBase
{
    private readonly IEventLogService _events;
    private List<SecurityEvent> _allEvents = new();

    private string _scanSummaryText = "No scans recorded yet.";
    private string _threatSummaryText = "No threat detections recorded yet.";
    private string _updateSummaryText = "No signature updates recorded yet.";
    private string _protectionSummaryText = "No protection changes recorded yet.";
    private string _searchQuery = string.Empty;
    private int _severityFilterIndex; // 0 = All, 1 = Alerts / Failures Only, 2 = Passed / Info Only

    public HistoryViewModel(IEventLogService events)
    {
        _events = events;
        RefreshCommand = new RelayCommand(LoadAsync);
    }

    public ObservableCollection<SecurityEvent> Events { get; } = new();
    public ObservableCollection<DailySecurityMetric> SevenDayChart { get; } = new();

    public RelayCommand RefreshCommand { get; }

    public string ScanSummaryText { get => _scanSummaryText; set => SetProperty(ref _scanSummaryText, value); }
    public string ThreatSummaryText { get => _threatSummaryText; set => SetProperty(ref _threatSummaryText, value); }
    public string UpdateSummaryText { get => _updateSummaryText; set => SetProperty(ref _updateSummaryText, value); }
    public string ProtectionSummaryText { get => _protectionSummaryText; set => SetProperty(ref _protectionSummaryText, value); }

    public string SearchQuery
    {
        get => _searchQuery;
        set
        {
            if (SetProperty(ref _searchQuery, value))
                ApplyFilter();
        }
    }

    public int SeverityFilterIndex
    {
        get => _severityFilterIndex;
        set
        {
            if (SetProperty(ref _severityFilterIndex, value))
                ApplyFilter();
        }
    }

    public async Task LoadAsync()
    {
        if (IsBusy)
            return;

        IsBusy = true;
        ClearMessages();
        try
        {
            var history = await _events.ReadRecentAsync(500);
            _allEvents = history.ToList();

            BuildSevenDayChart(_allEvents);
            ApplyFilter();

            var scans = _allEvents.Count(e => e.Type.Contains("scan", StringComparison.OrdinalIgnoreCase) || e.Type.Contains("audit", StringComparison.OrdinalIgnoreCase));
            var threats = _allEvents.Count(e => !e.Success || e.Type.Contains("threat", StringComparison.OrdinalIgnoreCase) || e.Type.Contains("tamper", StringComparison.OrdinalIgnoreCase));
            var updates = _allEvents.Count(e => e.Type.Contains("signature", StringComparison.OrdinalIgnoreCase) || e.Type.Contains("upgrade", StringComparison.OrdinalIgnoreCase));
            var protectionChanges = _allEvents.Count(e => e.Type.Contains("protection", StringComparison.OrdinalIgnoreCase) || e.Type.Contains("hardening", StringComparison.OrdinalIgnoreCase) || e.Type.Contains("killswitch", StringComparison.OrdinalIgnoreCase));

            ScanSummaryText = scans == 0 ? "No scans recorded yet." : $"{scans} scan/audit event(s).";
            ThreatSummaryText = threats == 0 ? "No alerts or failures recorded." : $"{threats} alert/failure event(s).";
            UpdateSummaryText = updates == 0 ? "No updates recorded yet." : $"{updates} update event(s).";
            ProtectionSummaryText = protectionChanges == 0 ? "No shield changes recorded." : $"{protectionChanges} shield/hardening change(s).";
        }
        finally
        {
            IsBusy = false;
        }
    }

    private void ApplyFilter()
    {
        IEnumerable<SecurityEvent> query = _allEvents;

        if (SeverityFilterIndex == 1)
            query = query.Where(e => !e.Success || e.Type.Contains("threat", StringComparison.OrdinalIgnoreCase) || e.Type.Contains("alert", StringComparison.OrdinalIgnoreCase));
        else if (SeverityFilterIndex == 2)
            query = query.Where(e => e.Success);

        if (!string.IsNullOrWhiteSpace(SearchQuery))
        {
            var q = SearchQuery.Trim();
            query = query.Where(e =>
                (e.Summary?.Contains(q, StringComparison.OrdinalIgnoreCase) ?? false) ||
                (e.Type?.Contains(q, StringComparison.OrdinalIgnoreCase) ?? false) ||
                (e.Detail?.Contains(q, StringComparison.OrdinalIgnoreCase) ?? false));
        }

        var filtered = query.ToList();
        Events.Clear();
        foreach (var ev in filtered)
            Events.Add(ev);

        StatusMessage = _allEvents.Count == 0
            ? "No events recorded yet. Events are written only when real actions happen."
            : $"Showing {filtered.Count} of {_allEvents.Count} recorded event(s).";
    }

    private void BuildSevenDayChart(IReadOnlyList<SecurityEvent> events)
    {
        var today = DateTimeOffset.Now.Date;
        var days = Enumerable.Range(0, 7).Select(offset => today.AddDays(-6 + offset)).ToList();

        var counts = days.Select(d =>
        {
            int total = events.Count(e => e.Timestamp.ToLocalTime().Date == d);
            int alerts = events.Count(e => e.Timestamp.ToLocalTime().Date == d && !e.Success);
            return (Day: d, Total: total, Alerts: alerts);
        }).ToList();

        int maxTotal = Math.Max(1, counts.Max(c => c.Total));
        const double maxBarPx = 92.0;

        SevenDayChart.Clear();
        foreach (var c in counts)
        {
            double totalHeight = c.Total == 0 ? 4.0 : Math.Max(10.0, (c.Total / (double)maxTotal) * maxBarPx);
            double alertHeight = c.Alerts == 0 ? 0.0 : Math.Max(8.0, (c.Alerts / (double)maxTotal) * maxBarPx);
            SevenDayChart.Add(new DailySecurityMetric
            {
                DayLabel = c.Day.ToString("ddd dd"),
                TotalCount = c.Total,
                AlertCount = c.Alerts,
                TotalBarHeight = totalHeight,
                AlertBarHeight = alertHeight
            });
        }
    }
}
