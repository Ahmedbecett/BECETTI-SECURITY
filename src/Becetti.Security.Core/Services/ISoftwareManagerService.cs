using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

/// <summary>
/// Real installed-software inventory from the same registry locations
/// Settings &gt; Apps reads. Uninstalling always launches the application's
/// own real uninstaller (UninstallString) — BECETTI SECURITY never deletes
/// files or registry entries itself.
/// </summary>
public interface ISoftwareManagerService
{
    Task<OperationResult<IReadOnlyList<InstalledAppInfo>>> GetInstalledAppsAsync();

    /// <summary>
    /// Launches the application's own real uninstaller process. This does not
    /// uninstall anything by itself — the native uninstaller then runs and
    /// shows its own confirmation/progress UI, same as Settings &gt; Apps &gt;
    /// Uninstall.
    /// </summary>
    OperationResult LaunchUninstaller(InstalledAppInfo app);
}
