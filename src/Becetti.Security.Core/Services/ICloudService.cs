using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

/// <summary>
/// Client for the BECETTI SECURITY cloud API (HTTPS REST). Every method
/// performs a real HTTP request and returns the real server response.
/// When no API URL is configured, methods fail with NOT_CONFIGURED instead
/// of returning invented data.
/// </summary>
public interface ICloudService
{
    bool IsConfigured { get; }
    bool IsAuthenticated { get; }
    string? AccessToken { get; }

    Task<OperationResult<CloudHealth>> GetHealthAsync(CancellationToken ct = default);
    Task<OperationResult<AuthTokens>> LoginAsync(string email, string password, CancellationToken ct = default);
    Task<OperationResult<AuthTokens>> RegisterAsync(string email, string password, CancellationToken ct = default);
    Task<OperationResult> LogoutAsync(CancellationToken ct = default);
    Task<OperationResult<ReputationVerdict>> CheckReputationAsync(string sha256, CancellationToken ct = default);
    Task<OperationResult<UpdateCheckResult>> CheckUpdatesAsync(string currentVersion, string channel = "stable", CancellationToken ct = default);
    Task<OperationResult<string>> GetCurrentUserEmailAsync(CancellationToken ct = default);
}
