namespace Becetti.Security.App.ViewModels;

/// <summary>One bubble in the BECETTI AI chat transcript.</summary>
public sealed class AiChatMessage
{
    public required bool IsFromUser { get; init; }
    public required string Text { get; init; }
    public DateTimeOffset Timestamp { get; init; } = DateTimeOffset.Now;

    /// <summary>True for a message still being sent/awaiting reply (shows a typing indicator look).</summary>
    public bool IsPending { get; init; }

    /// <summary>True when this bubble reports a real error (styled distinctly, never a normal reply).</summary>
    public bool IsError { get; init; }

    /// <summary>
    /// True when BECETTI AI signaled (via the backend's own honesty rules) that it
    /// could not genuinely resolve this question, so the UI offers a one-tap
    /// "open a support ticket" action under this specific message.
    /// </summary>
    public bool SuggestsSupportTicket { get; init; }
}
