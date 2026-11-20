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
    }

    public ObservableCollection<ThreatInfo> Threats { get; } = new();

    public RelayCommand RefreshCommand { get; }
    public RelayCommand RemoveSelectedCommand { get; }

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

            await LoadAsync();
        }
        finally
        {
            IsBusy = false;
        }
    }
}
