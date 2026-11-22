using System.ComponentModel.DataAnnotations;

namespace Becetti.Security.Api.Models;

public sealed class RegisterRequest
{
    [Required, EmailAddress, MaxLength(256)]
    public string Email { get; set; } = string.Empty;

    [Required, MinLength(10), MaxLength(128)]
    public string Password { get; set; } = string.Empty;
}

public sealed class LoginRequest
{
    [Required, EmailAddress, MaxLength(256)]
    public string Email { get; set; } = string.Empty;

    [Required, MaxLength(128)]
    public string Password { get; set; } = string.Empty;
}

public sealed class RefreshRequest
{
    [Required]
    public string RefreshToken { get; set; } = string.Empty;
}

public sealed class TokenResponse
{
    public string AccessToken { get; set; } = string.Empty;
    public string RefreshToken { get; set; } = string.Empty;
    public DateTimeOffset ExpiresAt { get; set; }
}

public sealed class MeResponse
{
    public string Email { get; set; } = string.Empty;
    public bool IsAdmin { get; set; }
}

public sealed class ReputationCheckRequest
{
    [Required, RegularExpression("^[0-9a-fA-F]{64}$", ErrorMessage = "sha256 must be 64 hexadecimal characters.")]
    public string Sha256 { get; set; } = string.Empty;
}

public sealed class ReputationResponse
{
    public string Sha256 { get; set; } = string.Empty;
    public string Verdict { get; set; } = "unknown";
    public string Source { get; set; } = string.Empty;
    public string? Detail { get; set; }
    public DateTimeOffset CheckedAt { get; set; }
}

public sealed class UpdateCheckResponse
{
    public string CurrentVersion { get; set; } = string.Empty;
    public string? LatestVersion { get; set; }
    public bool UpdateAvailable { get; set; }
    public string Channel { get; set; } = "stable";
    public string? ReleaseNotes { get; set; }
    public string? StoreUrl { get; set; }
}

public sealed class HealthResponse
{
    public string Status { get; set; } = "ok";
    public string Version { get; set; } = "1.0.0";
    public DateTimeOffset ServerTime { get; set; }
}

public sealed class DeviceHeartbeatRequest
{
    /// <summary>Stable identifier generated once on the device's own installation (not the database row Id).</summary>
    [Required, MaxLength(128)]
    public string DeviceId { get; set; } = string.Empty;

    [Required, MaxLength(128)]
    public string DeviceName { get; set; } = string.Empty;

    [Required, MaxLength(64)]
    public string Platform { get; set; } = string.Empty;

    [Required, MaxLength(32)]
    public string AppVersion { get; set; } = string.Empty;
}

public sealed class DeviceResponse
{
    public string DeviceId { get; set; } = string.Empty;
    public string DeviceName { get; set; } = string.Empty;
    public string Platform { get; set; } = string.Empty;
    public string AppVersion { get; set; } = string.Empty;
    public DateTimeOffset FirstSeenAt { get; set; }
    public DateTimeOffset LastSeenAt { get; set; }
}

public sealed class IntelStatsResponse
{
    public long TotalUsers { get; set; }
    public long TotalReputationEntries { get; set; }
    public long MaliciousEntries { get; set; }
    public long TotalReleases { get; set; }
    public long TotalAuditEvents { get; set; }
}

public sealed class ReputationIngestRequest
{
    [Required, RegularExpression("^[0-9a-fA-F]{64}$", ErrorMessage = "sha256 must be 64 hexadecimal characters.")]
    public string Sha256 { get; set; } = string.Empty;

    [Required, RegularExpression("^(clean|malicious|suspicious|unknown)$", ErrorMessage = "verdict must be clean, malicious, suspicious or unknown.")]
    public string Verdict { get; set; } = "unknown";

    [Required, MaxLength(64)]
    public string Source { get; set; } = string.Empty;

    [MaxLength(1024)]
    public string? Detail { get; set; }
}

public sealed class ReleasePublishRequest
{
    [Required, MaxLength(32)]
    public string Version { get; set; } = string.Empty;

    [MaxLength(32)]
    public string Channel { get; set; } = "stable";

    [MaxLength(8192)]
    public string? ReleaseNotes { get; set; }

    [MaxLength(1024)]
    public string? StoreUrl { get; set; }

    public bool IsMandatory { get; set; }
}
