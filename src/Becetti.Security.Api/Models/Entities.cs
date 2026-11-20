using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Becetti.Security.Api.Models;

/// <summary>Application user. Passwords are stored only as BCrypt hashes.</summary>
public sealed class User
{
    public Guid Id { get; set; } = Guid.NewGuid();

    [Required, MaxLength(256)]
    public string Email { get; set; } = string.Empty;

    [Required]
    public string PasswordHash { get; set; } = string.Empty;

    public bool IsAdmin { get; set; }

    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

    public ICollection<RefreshToken> RefreshTokens { get; set; } = new List<RefreshToken>();
}

/// <summary>Hashed refresh token (the raw token is only ever shown once, at issuance).</summary>
public sealed class RefreshToken
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public Guid UserId { get; set; }

    [Required]
    public string TokenHash { get; set; } = string.Empty;

    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? RevokedAt { get; set; }

    public User User { get; set; } = null!;
}

/// <summary>Cached file-reputation verdict. Only real provider responses are stored.</summary>
public sealed class ReputationEntry
{
    public Guid Id { get; set; } = Guid.NewGuid();

    [Required, MaxLength(64)]
    public string Sha256 { get; set; } = string.Empty;

    /// <summary>clean | malicious | suspicious | unknown</summary>
    [Required, MaxLength(32)]
    public string Verdict { get; set; } = "unknown";

    [Required, MaxLength(64)]
    public string Source { get; set; } = string.Empty;

    [MaxLength(1024)]
    public string? Detail { get; set; }

    public DateTimeOffset FirstSeenAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset LastCheckedAt { get; set; } = DateTimeOffset.UtcNow;
    public long TimesSeen { get; set; }
}

/// <summary>Published application release (for the update-check endpoint).</summary>
public sealed class ReleaseVersion
{
    public Guid Id { get; set; } = Guid.NewGuid();

    [Required, MaxLength(32)]
    public string Version { get; set; } = string.Empty;

    [Required, MaxLength(32)]
    public string Channel { get; set; } = "stable";

    [MaxLength(8192)]
    public string? ReleaseNotes { get; set; }

    [MaxLength(1024)]
    public string? StoreUrl { get; set; }

    public bool IsMandatory { get; set; }
    public DateTimeOffset PublishedAt { get; set; } = DateTimeOffset.UtcNow;
}

/// <summary>Server-side audit trail for security-relevant actions.</summary>
public sealed class AuditLog
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public DateTimeOffset Timestamp { get; set; } = DateTimeOffset.UtcNow;

    public Guid? UserId { get; set; }

    [Required, MaxLength(128)]
    public string Action { get; set; } = string.Empty;

    [MaxLength(2048)]
    public string? Detail { get; set; }

    [MaxLength(64)]
    public string? IpAddress { get; set; }
}
