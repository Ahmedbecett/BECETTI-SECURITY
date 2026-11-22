using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

/// <summary>Real device, OS and network checks. No values are assumed.</summary>
public interface ISystemInfoService
{
    Task<OperationResult<DeviceInfo>> GetDeviceInfoAsync(CancellationToken ct = default);
    Task<OperationResult<NetworkCheckResult>> CheckNetworkAsync(string? apiBaseUrl, CancellationToken ct = default);

    /// <summary>
    /// Reads the real device-wide Camera/Microphone/Location access switches
    /// from the CapabilityAccessManager ConsentStore — the same registry
    /// values Settings &gt; Privacy &amp; security itself reads and writes.
    /// </summary>
    Task<OperationResult<IReadOnlyList<PrivacyPermissionInfo>>> GetPrivacyPermissionsAsync(CancellationToken ct = default);
}
