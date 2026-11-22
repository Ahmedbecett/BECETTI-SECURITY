using System.Collections.ObjectModel;
using System.Text;
using System.Text.Json;
using Becetti.Security.App.Services;
using Becetti.Security.Core.Services;

namespace Becetti.Security.App.ViewModels;

/// <summary>
/// BECETTI AI chat page. Talks only to the BECETTI AI backend (never to an
/// AI provider directly, never with an embedded key). Every assistant bubble
/// is either a real backend reply or a real, clearly-labeled error — this
/// view model never invents a reply client-side. Optional, mutable extras:
/// reading replies aloud with the Windows TTS engine, and a one-tap "open a
/// support ticket" escalation that only ever prepares an email draft the
/// user must send themselves.
/// </summary>
public sealed class BecettiAiViewModel : ViewModelBase
{
    private const string SupportTicketSentinel = "[[OFFER_SUPPORT_TICKET]]";

    private readonly IBecettiAiService _ai;
    private readonly IDefenderService _defender;
    private readonly IYaraEngineService _yara;
    private readonly ISystemInfoService _system;
    private readonly ISettingsService _settings;
    private readonly SpeechService _speech;

    private string _inputText = string.Empty;
    private bool _isSending;
    private bool _shareDeviceState;
    private bool _saveHistory;
    private bool _voiceRepliesEnabled;
    private bool _isSpeaking;
    private string _lastDetectedLanguage = "en-US";

    public BecettiAiViewModel(IBecettiAiService ai, IDefenderService defender, IYaraEngineService yara, ISystemInfoService system, ISettingsService settings, SpeechService speech)
    {
        _ai = ai;
        _defender = defender;
        _yara = yara;
        _system = system;
        _settings = settings;
        _speech = speech;

        _shareDeviceState = settings.Current.AiShareDeviceState;
        _saveHistory = settings.Current.AiSaveHistory;
        _voiceRepliesEnabled = settings.Current.AiVoiceRepliesEnabled;

        _speech.SpeakingStarted += (_, _) => IsSpeaking = true;
        _speech.SpeakingEnded += (_, _) => IsSpeaking = false;

        SendCommand = new RelayCommand(SendAsync, () => !IsSending && !string.IsNullOrWhiteSpace(InputText));
        ClearCommand = new RelayCommand(ClearAsync);
        CreateSupportTicketCommand = new RelayCommand(CreateSupportTicketAsync);

        if (_saveHistory)
            LoadHistory();

        Messages.CollectionChanged += (_, _) => OnPropertyChanged(nameof(HasNoMessages));
    }

    public ObservableCollection<AiChatMessage> Messages { get; } = new();

    public RelayCommand SendCommand { get; }
    public RelayCommand ClearCommand { get; }
    public RelayCommand CreateSupportTicketCommand { get; }

    public bool HasNoMessages => Messages.Count == 0;

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

    /// <summary>True while a reply is actually being read aloud — drives the robot "talking" animation. Never faked.</summary>
    public bool IsSpeaking
    {
        get => _isSpeaking;
        private set => SetProperty(ref _isSpeaking, value);
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

    /// <summary>Read replies aloud with the Windows TTS engine. On by default; always one tap away from off.</summary>
    public bool VoiceRepliesEnabled
    {
        get => _voiceRepliesEnabled;
        set
        {
            if (SetProperty(ref _voiceRepliesEnabled, value))
            {
                _settings.Current.AiVoiceRepliesEnabled = value;
                _ = _settings.SaveAsync();
                if (!value)
                    _speech.Stop();
            }
        }
    }

    public bool IsConfigured => _ai.IsConfigured;

    /// <summary>
    /// Prefills the message box with a real report (e.g. a just-completed scan result or
    /// a specific Defender threat) so the user can review it and tap Send themselves —
    /// nothing is sent to BECETTI AI automatically just by navigating here.
    /// </summary>
    public void SeedInput(string text)
    {
        InputText = text;
    }

    /// <summary>
    /// Called once when the chat page first opens (empty conversation only)
    /// to show and, if enabled, speak the welcome greeting in the app's
    /// current UI language. Never runs again once a conversation exists.
    /// </summary>
    public async Task PlayWelcomeIfEmptyAsync(string welcomeText, string uiLanguageTag)
    {
        if (!HasNoMessages || !VoiceRepliesEnabled)
            return;

        _lastDetectedLanguage = uiLanguageTag;
        await _speech.SpeakAsync(welcomeText, uiLanguageTag);
    }

    private async Task SendAsync()
    {
        var text = InputText.Trim();
        if (string.IsNullOrWhiteSpace(text) || IsSending)
            return;

        ClearMessages();
        InputText = string.Empty;
        _speech.Stop();

        Messages.Add(new AiChatMessage { IsFromUser = true, Text = text });
        _lastDetectedLanguage = DetectLanguageTag(text);

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
                var raw = result.Value;
                var offersTicket = raw.Contains(SupportTicketSentinel, StringComparison.Ordinal);
                var displayText = offersTicket
                    ? raw.Replace(SupportTicketSentinel, string.Empty).TrimEnd()
                    : raw;

                Messages.Add(new AiChatMessage { IsFromUser = false, Text = displayText, SuggestsSupportTicket = offersTicket });
                StatusMessage = string.Empty;

                if (VoiceRepliesEnabled)
                    _ = _speech.SpeakAsync(displayText, _lastDetectedLanguage);
            }
            else
            {
                // A technical failure (offline, server error, not configured, etc.) is
                // just as much a case where BECETTI AI "could not solve it" as a plain
                // knowledge gap, so it must offer the same support-ticket escalation.
                Messages.Add(new AiChatMessage { IsFromUser = false, Text = result.Message, IsError = true, SuggestsSupportTicket = true });
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

    /// <summary>
    /// Best-effort language detection used only to pick a matching Windows
    /// TTS voice — never used to decide or alter the actual answer. Falls
    /// back to English when the text is ambiguous.
    /// </summary>
    private static string DetectLanguageTag(string text)
    {
        if (text.Any(c => c >= '\u0600' && c <= '\u06FF'))
            return "ar-SA";

        var lower = text.ToLowerInvariant();
        var frenchMarkers = new[] { "é", "è", "ê", "à", "ù", "ç", "œ", " le ", " la ", " les ", " est ", " bonjour", "merci", " vous ", " je ", " pas " };
        if (frenchMarkers.Any(lower.Contains))
            return "fr-FR";

        return "en-US";
    }

    private async Task<List<AiChatTurn>> BuildHistoryForRequestAsync()
    {
        var turns = new List<AiChatTurn>();

        // Real, live device-state context, only ever attached with the user's
        // explicit, persisted consent (ShareDeviceState) — never silently.
        string? contextPrefix = null;
        if (ShareDeviceState)
            contextPrefix = await BuildDeviceStateContextAsync();

        // Never send pending placeholders or past technical error bubbles as
        // conversation history to Gemini.
        foreach (var m in Messages.Where(m => !m.IsPending && !m.IsError && !string.IsNullOrWhiteSpace(m.Text)))
        {
            var role = m.IsFromUser ? "user" : "assistant";
            var content = m.Text;

            if (contextPrefix is not null && m.IsFromUser)
            {
                content = contextPrefix + "\n\n" + content;
                contextPrefix = null;
            }

            if (turns.Count > 0 && string.Equals(turns[^1].Role, role, StringComparison.Ordinal))
            {
                turns[^1] = new AiChatTurn { Role = role, Content = turns[^1].Content + "\n\n" + content };
            }
            else
            {
                turns.Add(new AiChatTurn { Role = role, Content = content });
            }
        }

        if (contextPrefix is not null)
            turns.Insert(0, new AiChatTurn { Role = "user", Content = contextPrefix });

        return turns;
    }

    private async Task<string?> BuildDeviceStateContextAsync()
    {
        var parts = new List<string>();
        try
        {
            var yara = await _yara.GetEngineInfoAsync();
            if (yara.Success && yara.Value is not null && yara.Value.IsAvailable)
            {
                parts.Add($"Native YARA Engine: v{yara.Value.Version} ({yara.Value.Architecture}), " +
                          $"{yara.Value.ValidRuleFiles} valid rule file(s) ({yara.Value.ActiveRuleCount} active rules).");
            }
            else
            {
                parts.Add($"Native YARA Engine: unavailable ({yara.Message}).");
            }
        }
        catch
        {
            // Optional context segment
        }

        try
        {
            var status = await _defender.GetStatusAsync();
            if (status.Success && status.Value is not null)
            {
                var s = status.Value;
                parts.Add($"Microsoft Defender — Antivirus enabled: {s.AntivirusEnabled}. Real-time protection: {s.RealTimeProtectionEnabled}. " +
                          $"Tamper protection: {s.TamperProtectionEnabled}. Cloud protection level: {s.CloudProtectionLevel}.");
            }
            else
            {
                parts.Add("Microsoft Defender status could not be read right now.");
            }
        }
        catch
        {
            // Optional context segment
        }

        if (parts.Count == 0)
            return null;

        return "[Real device context, read live just now — treat as ground truth, do not contradict it] " + string.Join(" ", parts);
    }

    /// <summary>
    /// Prepares a support-ticket email draft (subject includes a real,
    /// locally generated tracking number) in the user's own email app.
    /// Exactly like Contact Becetti: nothing is ever sent automatically —
    /// the user must review and press Send themselves.
    /// </summary>
    private async Task CreateSupportTicketAsync()
    {
        if (IsBusy)
            return;

        IsBusy = true;
        ClearMessages();
        try
        {
            var ticketId = $"BKT-{DateTime.UtcNow:yyyyMMdd-HHmmss}-{Guid.NewGuid().ToString("N")[..6].ToUpperInvariant()}";

            var body = new StringBuilder();
            body.AppendLine($"Support ticket: {ticketId}");
            body.AppendLine($"Created: {DateTimeOffset.Now:u}");
            body.AppendLine();
            body.AppendLine("--- BECETTI AI conversation (for context) ---");
            foreach (var m in Messages.Where(m => !m.IsPending))
                body.AppendLine($"[{(m.IsFromUser ? "User" : "BECETTI AI")}] {m.Text}");

            body.AppendLine();
            body.AppendLine("--- Describe what you still need help with below ---");
            body.AppendLine();

            try
            {
                var device = await _system.GetDeviceInfoAsync();
                if (device.Success && device.Value is not null)
                {
                    var d = device.Value;
                    body.AppendLine($"(Diagnostics: {d.OsDescription} build {d.OsBuild}, {d.Architecture})");
                }
            }
            catch
            {
                // Diagnostics are a courtesy only; never block ticket creation on them.
            }

            var subject = $"BECETTI SECURITY support ticket {ticketId}";
            var uri = $"mailto:{Uri.EscapeDataString(_settings.Current.SupportEmail)}?subject={Uri.EscapeDataString(subject)}&body={Uri.EscapeDataString(body.ToString())}";

            if (OperatingSystem.IsWindows())
            {
                var startInfo = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = uri,
                    UseShellExecute = true
                };
                System.Diagnostics.Process.Start(startInfo);

                Messages.Add(new AiChatMessage
                {
                    IsFromUser = false,
                    Text = $"Support ticket {ticketId} was prepared and your email app opened with it. Nothing is sent until you press Send there. Keep {ticketId} for your records."
                });
                StatusMessage = $"Ticket {ticketId} ready in your email app.";
            }
            else
            {
                ErrorMessage = "Opening the email app is only supported on Windows.";
            }
        }
        catch (Exception ex)
        {
            ErrorMessage = $"Could not prepare the support ticket: {ex.Message}";
        }
        finally
        {
            IsBusy = false;
        }
    }

    private Task ClearAsync()
    {
        _speech.Stop();
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
