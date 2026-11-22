using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

/// <summary>
/// Platform/identity security: real TPM, Secure Boot, Credential Guard and
/// BitLocker state via the official Get-Tpm / Confirm-SecureBootUEFI /
/// Win32_DeviceGuard / Get-BitLockerVolume sources, plus the real Windows
/// Update last-success time from the registry. BECETTI SECURITY implements
/// none of these security features itself — it only reads and explains them.
/// </summary>
public interface IPlatformSecurityService
{
    /// <summary>One combined read of TPM, Secure Boot, Credential Guard and BitLocker state.</summary>
    Task<OperationResult<PlatformSecuritySnapshot>> GetSnapshotAsync(CancellationToken ct = default);

    /// <summary>Real last-successful Windows Update install time from the registry.</summary>
    Task<OperationResult<WindowsUpdateStatus>> GetWindowsUpdateStatusAsync();
}
