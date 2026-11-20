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
