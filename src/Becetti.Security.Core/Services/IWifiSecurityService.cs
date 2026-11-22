using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

/// <summary>
/// Wi-Fi Security: reads the real currently-connected Wi-Fi network's
/// authentication/cipher from "netsh wlan show interfaces" — the same tool
/// and data Settings &gt; Network &amp; internet &gt; Wi-Fi itself is built
/// on. BECETTI SECURITY performs no network scanning of its own.
/// </summary>
public interface IWifiSecurityService
{
    Task<OperationResult<WifiSecurityInfo>> GetCurrentNetworkSecurityAsync(CancellationToken ct = default);
}
