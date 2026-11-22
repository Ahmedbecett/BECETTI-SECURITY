using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

/// <summary>
/// Network Monitor: real network adapters (.NET NetworkInterface, the same
/// source Windows' own Network Connections panel reads) and real active TCP
/// connections / listening ports (Get-NetTCPConnection, the same source
/// Resource Monitor's Network tab reads). BECETTI SECURITY makes no
/// independent judgement about which connections are "malicious" — it shows
/// Windows' own verified connection list and lets the user decide, same as
/// every other feature's no-fabrication rule.
/// </summary>
public interface INetworkMonitorService
{
    /// <summary>Enumerate real network adapters and their live state.</summary>
    Task<OperationResult<IReadOnlyList<NetworkAdapterInfo>>> GetAdaptersAsync();

    /// <summary>Read real active TCP connections and listening ports via Get-NetTCPConnection.</summary>
    Task<OperationResult<IReadOnlyList<NetworkConnectionInfo>>> GetActiveConnectionsAsync(CancellationToken ct = default);
}
