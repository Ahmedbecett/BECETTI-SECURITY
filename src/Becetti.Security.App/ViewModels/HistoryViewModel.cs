using System.Collections.ObjectModel;
using Becetti.Security.Core.Models;
using Becetti.Security.Core.Services;

namespace Becetti.Security.App.ViewModels;

/// <summary>Security History: the local log of real events recorded by the app.</summary>
public sealed class HistoryViewModel : ViewModelBase
{
    private readonly IEventLogService _events;

    public HistoryViewModel(IEventLogService events)
    {
        _events = events;
        RefreshCommand = new RelayCommand(LoadAsync);
    }

    public ObservableCollection<SecurityEvent> Events { get; } = new();

    public RelayCommand RefreshCommand { get; }

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
        }
        finally
        {
            IsBusy = false;
        }
    }
}
