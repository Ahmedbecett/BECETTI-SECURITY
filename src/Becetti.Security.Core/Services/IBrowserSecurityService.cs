using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

/// <summary>
/// Browser Security: detects real installed browsers from the same
/// installed-programs inventory Software Manager uses, and reads Windows'
/// own SmartScreen policy from the registry. BECETTI SECURITY implements no
/// browser extension or add-on of its own.
/// </summary>
public interface IBrowserSecurityService
{
    Task<OperationResult<IReadOnlyList<BrowserInfo>>> GetInstalledBrowsersAsync();

    Task<OperationResult<SmartScreenStatus>> GetSmartScreenStatusAsync();
}
