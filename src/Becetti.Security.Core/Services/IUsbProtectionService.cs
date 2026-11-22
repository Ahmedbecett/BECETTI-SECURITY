using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

/// <summary>
/// USB Protection: lists real currently-connected removable drives and
/// manages the real Windows AutoPlay/AutoRun policy (the setting that blocks
/// the classic autorun.inf USB-malware vector). BECETTI SECURITY never ships
/// its own USB scanning engine — scanning a drive is done by handing its
/// real path to Microsoft Defender (see IDefenderService.RunScanAsync).
/// </summary>
public interface IUsbProtectionService
{
    /// <summary>Enumerate real removable drives currently attached (System.IO.DriveInfo).</summary>
    Task<OperationResult<IReadOnlyList<UsbDriveInfo>>> GetConnectedDrivesAsync();

    /// <summary>Read the real Windows AutoPlay/AutoRun policy state.</summary>
    Task<OperationResult<UsbAutoRunStatus>> GetAutoRunStatusAsync();

    /// <summary>
    /// Enable or disable Windows' own AutoPlay/AutoRun block for removable
    /// drives (requires elevation to change the machine-wide policy).
    /// Verified by re-reading the registry before reporting success.
    /// </summary>
    Task<OperationResult> SetAutoRunProtectionAsync(bool enable);
}
