using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

/// <summary>Persisted application settings (no secrets here).</summary>
public sealed class AppSettings
{
    /// <summary>"en" or "ar".</summary>
    public string Language { get; set; } = "en";

    /// <summary>Cloud API base URL. Empty means cloud features are not configured.</summary>
    public string ApiBaseUrl { get; set; } = string.Empty;

    /// <summary>Telemetry is opt-in and OFF by default.</summary>
    public bool TelemetryOptIn { get; set; }

    /// <summary>"dark", "light" or "system". Default: dark (product design).</summary>
    public string Theme { get; set; } = "dark";

    /// <summary>Timestamp of the last scan that actually ran. Never fabricated.</summary>
    public DateTimeOffset? LastVerifiedScan { get; set; }

    public string? LastScanSummary { get; set; }

    /// <summary>Decorative UI animations (robot idle, shield glow, transitions). On by default; can be turned off (reduced motion).</summary>
    public bool EnableAnimations { get; set; } = true;

    /// <summary>Sound cues for genuine events only (scan completed, update completed, warnings). On by default.</summary>
    public bool EnableSounds { get; set; } = true;

    /// <summary>
    /// Base URL of the BECETTI AI backend (a small server that holds the real
    /// AI provider key; never embedded in this app). Points at the deployed
    /// BECETTI AI service by default; can be repointed in Settings.
    /// </summary>
    public string AiApiBaseUrl { get; set; } = "https://becetti-ai-backend-ahmed-d33b.vercel.app";

    /// <summary>
    /// Explicit, separate opt-in: when true, BECETTI AI may be given real,
    /// current app/device state (e.g. Defender status) as context for a
    /// question. OFF by default — the assistant must ask the user to turn
    /// this on rather than assuming consent.
    /// </summary>
    public bool AiShareDeviceState { get; set; }

    /// <summary>When true, BECETTI AI chat history is kept on disk between app runs. OFF by default.</summary>
    public bool AiSaveHistory { get; set; }

    /// <summary>Destination address for the "Contact Becetti" feature's prefilled email. Editable in Settings.</summary>
    public string SupportEmail { get; set; } = "ahmedbecetti35@gmail.com";
}

public interface ISettingsService
{
    AppSettings Current { get; }
    Task LoadAsync(CancellationToken ct = default);
    Task SaveAsync(CancellationToken ct = default);
    string DataDirectory { get; }
}

public interface ITokenStore
{
    /// <summary>True when tokens are protected with DPAPI.</summary>
    bool ProtectionActive { get; }
    Task SaveAsync(AuthTokens tokens, CancellationToken ct = default);
    Task<AuthTokens?> LoadAsync(CancellationToken ct = default);
    Task ClearAsync(CancellationToken ct = default);
}
