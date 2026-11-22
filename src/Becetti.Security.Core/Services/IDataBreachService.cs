using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

/// <summary>
/// Client for BECETTI SECURITY's data-breach monitoring proxy (see
/// /backend/becetti-ai). This class never talks to XposedOrNot or HIBP
/// directly — only the backend's own public URL, which also serves BECETTI
/// AI and VirusTotal. Every call is a real HTTP request; on any failure this
/// returns a real error — it never fabricates a "breached" or "clean"
/// result.
///
/// This is an optional, clearly-labelled second opinion on credential
/// exposure, independent of BECETTI SECURITY's core local protection.
/// </summary>
public interface IDataBreachService
{
    bool IsConfigured { get; }

    /// <summary>Checks whether an email address appears in any known public data breach.</summary>
    Task<OperationResult<EmailBreachReport>> CheckEmailAsync(string email, CancellationToken ct = default);

    /// <summary>
    /// Checks whether a password has appeared in HIBP's Pwned Passwords corpus.
    /// The password is hashed locally (SHA-1) and only a 5-character prefix of
    /// that hash is ever sent over the network — the password itself and the
    /// full hash never leave this process.
    /// </summary>
    Task<OperationResult<PasswordBreachReport>> CheckPasswordAsync(string password, CancellationToken ct = default);
}
