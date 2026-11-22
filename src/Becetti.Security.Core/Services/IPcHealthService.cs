using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

/// <summary>
/// Real, live PC health: CPU and RAM usage (GetSystemTimes / GlobalMemoryStatusEx,
/// official Win32 APIs), disk free space (DriveInfo, official .NET API over the
/// Windows volume APIs), and the run state of a handful of security-relevant
/// Windows services (ServiceController, the official Windows Service Control
/// Manager API). Nothing here is estimated, cached, or randomized.
/// </summary>
public interface IPcHealthService
{
    Task<OperationResult<PcHealthSnapshot>> GetSnapshotAsync(CancellationToken ct = default);
}
