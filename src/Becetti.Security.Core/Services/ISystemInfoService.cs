using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

/// <summary>Real device, OS and network checks. No values are assumed.</summary>
public interface ISystemInfoService
{
    Task<OperationResult<DeviceInfo>> GetDeviceInfoAsync(CancellationToken ct = default);
    Task<OperationResult<NetworkCheckResult>> CheckNetworkAsync(string? apiBaseUrl, CancellationToken ct = default);
}
