using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

/// <summary>
/// Real Windows startup-apps inventory: the same Run-key registry locations
/// and StartupApproved enabled/disabled convention that Task Manager's
/// "Startup apps" tab itself reads and writes. No fabricated data: an entry
/// is only ever listed if it genuinely exists in the registry.
/// </summary>
public interface IStartupManagerService
{
    Task<OperationResult<IReadOnlyList<StartupItemInfo>>> GetStartupItemsAsync();

    /// <summary>
    /// Enables or disables one real startup entry. Requires administrator
    /// rights for machine-wide (HKLM) entries; per-user (HKCU) entries can
    /// always be changed by the signed-in user, matching Windows' own rule.
    /// The new state is re-read from the registry before success is reported.
    /// </summary>
    Task<OperationResult> SetEnabledAsync(StartupItemInfo item, bool enabled);
}
