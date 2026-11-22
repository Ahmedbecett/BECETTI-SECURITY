using System.Security.Principal;

namespace Becetti.Security.Core.Services;

/// <summary>
/// Shared "is this process running as Administrator" check, used by every
/// feature that needs to gate a sensitive Windows change (Defender
/// preferences, startup entries, ...) behind real elevation rather than
/// guessing or always allowing it.
/// </summary>
public static class ElevationHelper
{
    public static bool IsElevated()
    {
        if (!OperatingSystem.IsWindows())
            return false;

        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }
}
