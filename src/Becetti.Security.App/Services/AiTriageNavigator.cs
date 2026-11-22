namespace Becetti.Security.App.Services;

/// <summary>
/// Contextual BECETTI AI Triage Bus: allows any security tool (Persistence Hunter,
/// PowerShell/LOLBins Auditor, Phishing URL Inspector, Browser Extensions Auditor,
/// Wi-Fi/ARP Guard, Unsigned DLL Inspector, etc.) to send a suspicious finding
/// directly to BECETTI AI for instant forensic analysis &amp; remediation guidance.
/// </summary>
public interface IAiTriageNavigator
{
    event EventHandler<string>? TriageRequested;
    string? ConsumePendingPrompt();
    void SendToBecettiAi(string structuredPrompt);
}

public sealed class AiTriageNavigator : IAiTriageNavigator
{
    private readonly object _lock = new();
    private string? _pendingPrompt;

    public event EventHandler<string>? TriageRequested;

    public string? ConsumePendingPrompt()
    {
        lock (_lock)
        {
            var p = _pendingPrompt;
            _pendingPrompt = null;
            return p;
        }
    }

    public void SendToBecettiAi(string structuredPrompt)
    {
        if (string.IsNullOrWhiteSpace(structuredPrompt))
            return;

        lock (_lock)
        {
            _pendingPrompt = structuredPrompt.Trim();
        }
        TriageRequested?.Invoke(this, structuredPrompt.Trim());
    }
}
