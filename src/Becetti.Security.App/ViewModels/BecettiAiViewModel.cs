using System.Collections.ObjectModel;
using System.Text.Json;
using Becetti.Security.Core.Services;

namespace Becetti.Security.App.ViewModels;

/// <summary>
/// BECETTI AI chat page. Talks only to the BECETTI AI backend (never to an
/// AI provider directly, never with an embedded key). Every assistant bubble
/// is either a real backend reply or a real, clearly-labeled error — this
/// view model never invents a reply client-side.
/// </summary>
public sealed class BecettiAiViewModel : ViewModelBase
{
    private readonly IBecettiAiService _ai;
    private readonly IDefenderService _defender;
    private readonly ISettingsService _settings;

    private string _inputText = string.Empty;
    private bool _isSending;
    private bool _shareDeviceState;
    private bool _saveHistory;

    public BecettiAiViewModel(IBecettiAiService ai, IDefenderService defender, ISettingsService settings)
    {
        _ai = ai;
        _defender = defender;
        _settings = settings;

        _shareDeviceState = settings.Current.AiShareDeviceState;
        _saveHistory = settings.Current.AiSaveHistory;

        SendCommand = new RelayCommand(SendAsync, () => !IsSending && !string.IsNullOrWhiteSpace(InputText));
        ClearCommand = new RelayCommand(ClearAsync);

        if (_saveHistory)
            LoadHistory();
    }

    public ObservableCollection<AiChatMessage> Messages { get; } = new();

    public RelayCommand SendCommand { get; }
    public RelayCommand ClearCommand { get; }

    public string InputText
    {
        get => _inputText;
        set
        {
            if (SetProperty(ref _inputText, value))
                SendCommand.RaiseCanExecuteChanged();
        }
    }

    public bool IsSending
    {
        get => _isSending;
        private set
        {
            if (SetProperty(ref _isSending, value))
                SendCommand.RaiseCanExecuteChanged();
        }
    }

    /// <summary>Explicit per-user consent to attach real, live app/device state to the next message. OFF by default.</summary>
    public bool ShareDeviceState
    {
        get => _shareDeviceState;
        set
        {
            if (SetProperty(ref _shareDeviceState, value))
            {
                _settings.Current.AiShareDeviceState = value;
                _ = _settings.SaveAsync();
            }
        }
    }

    public bool SaveHistory
    {
        get => _saveHistory;
        set
        {
            if (SetProperty(ref _saveHistory, value))
            {
                _settings.Current.AiSaveHistory = value;
                _ = _settings.SaveAsync();
                if (!value)
                    DeleteHistoryFile();
            }
        }
    }

    public bool IsConfigured => _ai.IsConfigured;

    private async Task SendAsync()
    {
        var text = InputText.Trim();
        if (string.IsNullOrWhiteSpace(text) || IsSending)
            return;

        ClearMessages();
        InputText = string.Empty;

        Messages.Add(new AiChatMessage { IsFromUser = true, Text = text });

        var pending = new AiChatMessage { IsFromUser = false, Text = string.Empty, IsPending = true };
        Messages.Add(pending);

        IsSending = true;
        try
        {
            var history = await BuildHistoryForRequestAsync();
            var result = await _ai.SendAsync(history);

            Messages.Remove(pending);

            if (result.Success && result.Value is not null)
            {
                Messages.Add(new AiChatMessage { IsFromUser = false, Text = result.Value });
                StatusMessage = string.Empty;
            }
            else
            {
                Messages.Add(new AiChatMessage { IsFromUser = false, Text = result.Message, IsError = true });
                ErrorMessage = result.Message;
            }

            if (SaveHistory)
                SaveHistoryToDisk();
        }
        finally
        {
            IsSending = false;
        }
    }

    private async Task<List<AiChatTurn>> BuildHistoryForRequestAsync()
    {
        var turns = new List<AiChatTurn>();

        // Real, live device-state context, only ever attached with the user's
        // explicit, persisted consent (ShareDeviceState) — never silently.
        if (ShareDeviceState)
        {
            var contextLine = await BuildDeviceStateContextAsync();
            if (!string.IsNullOrWhiteSpace(contextLine))
                turns.Add(new AiChatTurn { Role = "user", Content = contextLine });
        }

        foreach (var m in Messages.Where(m => !m.IsPending))
            turns.Add(new AiChatTurn { Role = m.IsFromUser ? "user" : "assistant", Content = m.Text });

        return turns;
    }

    private async Task<string?> BuildDeviceStateContextAsync()
    {
        try
        {
            var status = await _defender.GetStatusAsync();
            if (!status.Success || status.Value is null)
                return "[Real device context] Microsoft Defender status could not be read right now.";

            var s = status.Value;
            return "[Real device context, read just now from Microsoft Defender — treat as ground truth, do not contradict it] "
                + $"Antivirus enabled: {s.AntivirusEnabled}. Real-time protection: {s.RealTimeProtectionEnabled}. "
                + $"Tamper protection: {s.TamperProtectionEnabled}. Cloud protection level: {s.CloudProtectionLevel}.";
        }
        catch
        {
            return null;
        }
    }

    private Task ClearAsync()
    {
        Messages.Clear();
        DeleteHistoryFile();
        ClearMessages();
        return Task.CompletedTask;
    }

    private string HistoryPath => Path.Combine(_settings.DataDirectory, "becetti-ai-history.json");

    private void LoadHistory()
    {
        try
        {
            if (!File.Exists(HistoryPath))
                return;

            var json = File.ReadAllText(HistoryPath);
            var saved = JsonSerializer.Deserialize<List<PersistedMessage>>(json);
            if (saved is null)
                return;

            foreach (var m in saved)
                Messages.Add(new AiChatMessage { IsFromUser = m.IsFromUser, Text = m.Text, Timestamp = m.Timestamp });
        }
        catch
        {
            // Corrupt or unreadable history must never crash the chat page.
        }
    }

    private void SaveHistoryToDisk()
    {
        try
        {
            Directory.CreateDirectory(_settings.DataDirectory);
            var data = Messages
                .Where(m => !m.IsPending)
                .Select(m => new PersistedMessage { IsFromUser = m.IsFromUser, Text = m.Text, Timestamp = m.Timestamp })
                .ToList();
            File.WriteAllText(HistoryPath, JsonSerializer.Serialize(data));
        }
        catch
        {
            // Best-effort only; never block the chat on a disk write failure.
        }
    }

    private void DeleteHistoryFile()
    {
        try
        {
            if (File.Exists(HistoryPath))
                File.Delete(HistoryPath);
        }
        catch
        {
            // Ignore — not critical.
        }
    }

    private sealed class PersistedMessage
    {
        public bool IsFromUser { get; set; }
        public string Text { get; set; } = string.Empty;
        public DateTimeOffset Timestamp { get; set; }
    }
}
