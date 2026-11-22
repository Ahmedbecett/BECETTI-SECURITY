using System.Collections.ObjectModel;
using Becetti.Security.Core.Models;
using Becetti.Security.Core.Services;

namespace Becetti.Security.App.ViewModels;

/// <summary>
/// Threat Management: lists real Defender detections and removes them through
/// Defender (Remove-MpThreat). Removal is confirmed by re-querying Defender.
/// </summary>
public sealed class ThreatsViewModel : ViewModelBase
{
    private readonly IDefenderService _defender;
    private readonly IEventLogService _events;

    private ThreatInfo? _selectedThreat;

    public ThreatsViewModel(IDefenderService defender, IEventLogService events)
    {
        _defender = defender;
        _events = events;
        RefreshCommand = new RelayCommand(LoadAsync);
        RemoveSelectedCommand = new RelayCommand(RemoveSelectedAsync);
        OpenWindowsSecurityCommand = new RelayCommand(OpenWindowsSecurity);
    }

    public ObservableCollection<ThreatInfo> Threats { get; } = new();

    public RelayCommand RefreshCommand { get; }
    public RelayCommand RemoveSelectedCommand { get; }
    /// <summary>Opens Windows Security's Protection History / quarantine view directly.</summary>
    public RelayCommand OpenWindowsSecurityCommand { get; }

    public ThreatInfo? SelectedThreat
    {
        get => _selectedThreat;
        set => SetProperty(ref _selectedThreat, value);
    }

    public async Task LoadAsync()
    {
        if (IsBusy)
            return;

        IsBusy = true;
        ClearMessages();
        try
        {
            var result = await _defender.GetThreatsAsync();
            Threats.Clear();

            if (!result.Success || result.Value is null)
            {
                ErrorMessage = result.Message;
                StatusMessage = "Threat list unavailable.";
                return;
            }

            foreach (var threat in result.Value)
                Threats.Add(threat);

            StatusMessage = Threats.Count == 0
                ? "Microsoft Defender reports no threat detections."
                : $"Microsoft Defender reports {Threats.Count} detection(s).";
        }
        finally
        {
            IsBusy = false;
        }
    }

    private async Task RemoveSelectedAsync()
    {
        if (IsBusy)
            return;

        if (SelectedThreat is null)
        {
            ErrorMessage = "Select a threat first.";
            return;
        }

        IsBusy = true;
        ClearMessages();
        try
        {
            var result = await _defender.RemoveThreatAsync(SelectedThreat.ThreatId);
            if (result.Success)
            {
                StatusMessage = result.Message;
                await _events.RecordAsync("threat.removed", result.Message, true, SelectedThreat.ThreatId);
            }
            else
            {
                ErrorMessage = result.Message;
                await _events.RecordAsync("threat.remove.failed", result.Message, false, SelectedThreat.ThreatId);
            }
        }
        finally
        {
            IsBusy = false;
        }

        await LoadAsync();
    }

    /// <summary>
    /// Builds a plain-text prompt from the selected real Defender threat for BECETTI AI to
    /// explain — every field comes straight from Defender's own detection record, never
    /// invented. Returns null if nothing is selected.
    /// </summary>
    public string? BuildAiExplainPrompt()
    {
        if (SelectedThreat is null)
            return null;

        var t = SelectedThreat;
        return "Please explain this real Microsoft Defender threat detection from BECETTI SECURITY's Threat Management in plain language, and tell me if I need to do anything next:\n" +
               $"- Threat name: {t.ThreatName}\n" +
               $"- Severity: {t.Severity}\n" +
               $"- Category: {t.Category}\n" +
               (string.IsNullOrWhiteSpace(t.Resources) ? string.Empty : $"- Affected resource: {t.Resources}\n") +
               (t.DetectedAt.HasValue ? $"- Detected at: {t.DetectedAt.Value:u}\n" : string.Empty) +
               $"- Action taken by Defender: {(string.IsNullOrWhiteSpace(t.ActionTaken) ? "none recorded" : t.ActionTaken)}\n" +
               $"- Action succeeded: {t.ActionSucceeded}\n";
    }

    /// <summary>
    /// Opens the real Windows Security "Protection history" view (quarantine, recovery
    /// actions BECETTI SECURITY does not duplicate). Official windowsdefender: URI only.
    /// </summary>
    private Task OpenWindowsSecurity()
    {
        try
        {
            if (OperatingSystem.IsWindows())
            {
                var startInfo = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "windowsdefender://threat",
                    UseShellExecute = true
                };
                System.Diagnostics.Process.Start(startInfo);
                StatusMessage = "Opening Windows Security…";
            }
            else
            {
                ErrorMessage = "Windows Security can only be opened on Windows.";
            }
        }
        catch (Exception ex)
        {
            ErrorMessage = $"Could not open Windows Security: {ex.Message}";
        }

        return Task.CompletedTask;
    }
}
