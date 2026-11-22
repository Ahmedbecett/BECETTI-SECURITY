using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

/// <summary>
/// Real installed device driver inventory from WMI's Win32_PnPSignedDriver —
/// the same class Device Manager itself is built on. BECETTI SECURITY has no
/// driver vulnerability/known-issue database of its own, so it never invents
/// one here; it only reports what is genuinely installed and points the user
/// to Windows Update / the manufacturer as the official update source.
/// </summary>
public interface IDriverMonitorService
{
    Task<OperationResult<IReadOnlyList<DriverInfo>>> GetDriversAsync();
}
