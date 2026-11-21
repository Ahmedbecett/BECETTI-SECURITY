using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

/// <summary>One turn of the BECETTI AI conversation sent to the backend.</summary>
public sealed class AiChatTurn
{
    public required string Role { get; init; } // "user" or "assistant"
    public required string Content { get; init; }
}

/// <summary>
/// Client for the BECETTI AI backend. The backend (not this app) holds the
/// real AI provider key. Every call is a real HTTP request; on any failure
/// (not configured, offline, rate-limited, upstream error) this returns a
/// real error — it never fabricates a reply.
/// </summary>
public interface IBecettiAiService
{
    bool IsConfigured { get; }

    Task<OperationResult<string>> SendAsync(IReadOnlyList<AiChatTurn> history, CancellationToken ct = default);
}
