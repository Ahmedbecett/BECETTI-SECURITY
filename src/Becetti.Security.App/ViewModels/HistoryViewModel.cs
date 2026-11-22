using System.Collections.ObjectModel;
using Becetti.Security.Core.Models;
using Becetti.Security.Core.Services;

namespace Becetti.Security.App.ViewModels;

/// <summary>Security History: the local log of real events recorded by the app.</summary>
public sealed class HistoryViewModel : ViewModelBase
{
    private readonly IEventLogService _events;

    private string _scanSummaryText = "No scans recorded yet.";
    private string _threatSummaryText = "No threat detections recorded yet.";
    private string _updateSummaryText = "No signature updates recorded yet.";
    private string _protectionSummaryText = "No protection changes recorded yet.";

    public HistoryViewModel(IEventLogService events)
    {
        _events = events;
        RefreshCommand = new RelayCommand(LoadAsync);
    }

    public ObservableCollection<SecurityEvent> Events { get; } = new();

    public RelayCommand RefreshCommand { get; }

    public string ScanSummaryText { get => _scanSummaryText; set => SetProperty(ref _scanSummaryText, value); }
    public string ThreatSummaryText { get => _threatSummaryText; set => SetProperty(ref _threatSummaryText, value); }
    public string UpdateSummaryText { get => _updateSummaryText; set => SetProperty(ref _updateSummaryText, value); }
    public string ProtectionSummaryText { get => _protectionSummaryText; set => SetProperty(ref _protectionSummaryText, value); }

    public async Task LoadAsync()
    {
        if (IsBusy)
            return;

        IsBusy = true;
        ClearMessages();
        try
        {
            var history = await _events.ReadRecentAsync(500);
            Events.Clear();
            foreach (var securityEvent in history)
                Events.Add(securityEvent);

            StatusMessage = Events.Count == 0
                ? "No events recorded yet. Events are written only when real actions happen."
                : $"Showing {Events.Count} recorded event(s).";

            // Real counts only, computed from the events actually recorded above.
            // An empty history is shown as empty — nothing here is invented.
            var scans = Events.Count(e => e.Type is "scan.completed" or "scan.threat" or "scan.failed");
            var threats = Events.Count(e => e.Type is "scan.threat" or "threat.removed" or "threat.remove.failed");
            var updates = Events.Count(e => e.Type is "signatures.updated" or "signatures.failed");
            var protectionChanges = Events.Count(e => e.Type is "protection.changed" or "protection.failed");

            ScanSummaryText = scans == 0 ? "No scans recorded yet." : $"{scans} scan(s) recorded.";
            ThreatSummaryText = threats == 0 ? "No threat detections or removals recorded yet." : $"{threats} threat-related event(s) recorded.";
            UpdateSummaryText = updates == 0 ? "No signature updates recorded yet." : $"{updates} signature update attempt(s) recorded.";
            ProtectionSummaryText = protectionChanges == 0 ? "No protection changes recorded yet." : $"{protectionChanges} real-time protection change(s) recorded.";
        }
        finally
        {
            IsBusy = false;
        }
    }
}
