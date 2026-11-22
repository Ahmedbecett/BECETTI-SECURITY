using System.ComponentModel;
using System.Runtime.CompilerServices;
using Becetti.Security.Core.Models;

namespace Becetti.Security.App.ViewModels;

/// <summary>
/// Live scan status for one URL extracted from pasted email/message content
/// (see ThreatIntelligenceViewModel's email/link scanner). Mutable and
/// implements INotifyPropertyChanged so the list view updates in place as
/// each link is scanned, instead of needing to replace list items.
/// </summary>
public sealed class EmailLinkScanStatus : INotifyPropertyChanged
{
    private string _state = "Not scanned";
    private string? _detectionRatio;
    private ThreatIntelVerdict _verdict = ThreatIntelVerdict.Unknown;
    private string? _permalink;

    public EmailLinkScanStatus(string url)
    {
        Url = url;
    }

    public string Url { get; }

    public string State
    {
        get => _state;
        private set => SetProperty(ref _state, value);
    }

    public string? DetectionRatio
    {
        get => _detectionRatio;
        private set => SetProperty(ref _detectionRatio, value);
    }

    public ThreatIntelVerdict Verdict
    {
        get => _verdict;
        private set
        {
            if (SetProperty(ref _verdict, value))
            {
                OnPropertyChanged(nameof(IsClean));
                OnPropertyChanged(nameof(IsMalicious));
                OnPropertyChanged(nameof(IsSuspicious));
            }
        }
    }

    public string? Permalink
    {
        get => _permalink;
        private set => SetProperty(ref _permalink, value);
    }

    public bool IsClean => Verdict == ThreatIntelVerdict.Clean;
    public bool IsMalicious => Verdict == ThreatIntelVerdict.Malicious;
    public bool IsSuspicious => Verdict == ThreatIntelVerdict.Suspicious;

    public void MarkScanning() => State = "Scanning…";

    public void ApplyReport(ThreatIntelReport report)
    {
        Verdict = report.Verdict;
        DetectionRatio = report.DetectionRatio;
        Permalink = report.Permalink;
        State = report.Status switch
        {
            ThreatIntelStatus.Completed => $"{report.Verdict} ({report.DetectionRatio})",
            ThreatIntelStatus.Queued => "Still scanning on VirusTotal…",
            ThreatIntelStatus.NotFound => "No existing VirusTotal report",
            _ => report.Message
        };
    }

    public void MarkError(string message) => State = message;

    public event PropertyChangedEventHandler? PropertyChanged;

    private bool SetProperty<T>(ref T storage, T value, [CallerMemberName] string propertyName = "")
    {
        if (EqualityComparer<T>.Default.Equals(storage, value))
            return false;

        storage = value;
        OnPropertyChanged(propertyName);
        return true;
    }

    private void OnPropertyChanged([CallerMemberName] string propertyName = "") =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
}
