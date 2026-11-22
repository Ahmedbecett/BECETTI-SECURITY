using Microsoft.Win32;
using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

/// <summary>
/// USB Protection: real removable-drive inventory via System.IO.DriveInfo
/// (the same API Windows Explorer's drive list is built on) and the real
/// Windows AutoPlay/AutoRun group policy registry values. No independent USB
/// scanning engine is implemented here — scanning a drive is delegated to
/// Microsoft Defender via its real path (see IDefenderService.RunScanAsync).
/// </summary>
public sealed class UsbProtectionService : IUsbProtectionService
{
    private const string PoliciesExplorerPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer";
    private const string NoDriveTypeAutoRunValue = "NoDriveTypeAutoRun";
    private const string NoAutorunValue = "NoAutorun";

    /// <summary>Bit that blocks autorun on removable drives within NoDriveTypeAutoRun (per Microsoft's documented bitmask).</summary>
    private const int RemovableDriveBit = 0x4;

    public Task<OperationResult<IReadOnlyList<UsbDriveInfo>>> GetConnectedDrivesAsync() =>
        Task.Run(() => GetConnectedDrives());

    private static OperationResult<IReadOnlyList<UsbDriveInfo>> GetConnectedDrives()
    {
        try
        {
            var drives = new List<UsbDriveInfo>();
            foreach (var drive in DriveInfo.GetDrives())
            {
                if (drive.DriveType != DriveType.Removable)
                    continue;

                try
                {
                    drives.Add(new UsbDriveInfo
                    {
                        RootPath = drive.RootDirectory.FullName,
                        VolumeLabel = drive.IsReady ? SafeVolumeLabel(drive) : null,
                        FileSystem = drive.IsReady ? SafeDriveFormat(drive) : null,
                        TotalSizeBytes = drive.IsReady ? drive.TotalSize : null,
                        AvailableFreeBytes = drive.IsReady ? drive.AvailableFreeSpace : null,
                        IsReady = drive.IsReady
                    });
                }
                catch (IOException)
                {
                    // A drive that was just ejected mid-enumeration should not fail the whole list.
                }
            }

            return OperationResult<IReadOnlyList<UsbDriveInfo>>.Ok(
                drives,
                drives.Count == 0
                    ? "No removable (USB) drives are currently connected."
                    : $"{drives.Count} removable drive(s) currently connected.");
        }
        catch (Exception ex)
        {
            return OperationResult<IReadOnlyList<UsbDriveInfo>>.Fail($"Could not list removable drives: {ex.Message}", "DRIVE_ENUM_ERROR");
        }
    }

    private static string? SafeVolumeLabel(DriveInfo drive)
    {
        try { return string.IsNullOrWhiteSpace(drive.VolumeLabel) ? null : drive.VolumeLabel; }
        catch (IOException) { return null; }
    }

    private static string? SafeDriveFormat(DriveInfo drive)
    {
        try { return drive.DriveFormat; }
        catch (IOException) { return null; }
    }

    /// <summary>
    /// Interprets the real NoDriveTypeAutoRun DWORD: null means the policy value is not
    /// set at all (not the same as "allowed" — see UsbAutoRunStatus's own doc comment).
    /// </summary>
    internal static bool? InterpretRemovableBlocked(int? noDriveTypeAutoRun) =>
        noDriveTypeAutoRun.HasValue ? (noDriveTypeAutoRun.Value & RemovableDriveBit) == RemovableDriveBit : null;

    /// <summary>Interprets the real NoAutorun DWORD: null means the value is not set at all.</summary>
    internal static bool? InterpretAutorunInfDisabled(int? noAutorun) =>
        noAutorun.HasValue ? noAutorun.Value != 0 : null;

    /// <summary>
    /// Flips only the removable-drive bit BECETTI SECURITY owns within an existing
    /// NoDriveTypeAutoRun value, preserving any other bits an administrator already set
    /// for other drive types (CD-ROM, network, ...).
    /// </summary>
    internal static int ApplyRemovableBit(int current, bool blockRemovable) =>
        blockRemovable ? current | RemovableDriveBit : current & ~RemovableDriveBit;

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    public Task<OperationResult<UsbAutoRunStatus>> GetAutoRunStatusAsync()
    {
        if (!OperatingSystem.IsWindows())
            return Task.FromResult(OperationResult<UsbAutoRunStatus>.Fail("USB Protection is only available on Windows.", "UNSUPPORTED_OS"));

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(PoliciesExplorerPath);

            var noDriveTypeAutoRun = key?.GetValue(NoDriveTypeAutoRunValue);
            var noAutorun = key?.GetValue(NoAutorunValue);

            var removableBlocked = InterpretRemovableBlocked(noDriveTypeAutoRun as int?);
            var autorunInfDisabled = InterpretAutorunInfDisabled(noAutorun as int?);

            return Task.FromResult(OperationResult<UsbAutoRunStatus>.Ok(
                new UsbAutoRunStatus
                {
                    Available = true,
                    RemovableAutoRunBlocked = removableBlocked,
                    AutorunInfDisabled = autorunInfDisabled
                },
                "AutoRun policy read from the Windows registry."));
        }
        catch (Exception ex)
        {
            return Task.FromResult(OperationResult<UsbAutoRunStatus>.Fail(
                $"Could not read the AutoRun policy: {ex.Message}", "REGISTRY_ERROR"));
        }
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    public Task<OperationResult> SetAutoRunProtectionAsync(bool enable)
    {
        if (!OperatingSystem.IsWindows())
            return Task.FromResult(OperationResult.Fail("USB Protection is only available on Windows.", "UNSUPPORTED_OS"));

        if (!ElevationHelper.IsElevated())
            return Task.FromResult(OperationResult.Fail(
                "Changing the AutoRun policy requires an administrator. Restart BECETTI SECURITY as administrator from Settings.",
                "ELEVATION_REQUIRED"));

        try
        {
            using var key = Registry.LocalMachine.CreateSubKey(PoliciesExplorerPath, writable: true);
            if (key is null)
                return Task.FromResult(OperationResult.Fail("Could not open the AutoRun policy key for writing.", "REGISTRY_UNAVAILABLE"));

            // Preserve any other bits an administrator may already have set for other drive
            // types (CD-ROM, network, ...) — only flip the removable-drive bit this feature owns.
            var current = key.GetValue(NoDriveTypeAutoRunValue) is int existing ? existing : 0;
            var updated = ApplyRemovableBit(current, enable);

            key.SetValue(NoDriveTypeAutoRunValue, updated, RegistryValueKind.DWord);
            key.SetValue(NoAutorunValue, enable ? 1 : 0, RegistryValueKind.DWord);

            // Re-verify from the registry rather than assuming the write succeeded as asked.
            var confirmedDriveType = key.GetValue(NoDriveTypeAutoRunValue) is int cd ? cd : 0;
            var confirmedAutorun = key.GetValue(NoAutorunValue) is int ca ? ca : 0;
            var removableNowBlocked = InterpretRemovableBlocked(confirmedDriveType) == true;
            var autorunNowDisabled = InterpretAutorunInfDisabled(confirmedAutorun) == true;

            if (removableNowBlocked != enable || autorunNowDisabled != enable)
                return Task.FromResult(OperationResult.Fail("The AutoRun policy could not be confirmed after the change.", "VERIFICATION_FAILED"));

            return Task.FromResult(OperationResult.Ok(enable
                ? "AutoRun/AutoPlay is now blocked for removable drives — the classic autorun.inf USB infection vector is disabled."
                : "The AutoRun block BECETTI SECURITY applied has been removed. Windows' own built-in autorun hardening may still apply."));
        }
        catch (UnauthorizedAccessException)
        {
            return Task.FromResult(OperationResult.Fail("Access denied changing the AutoRun policy. Try running BECETTI SECURITY as administrator.", "ACCESS_DENIED"));
        }
        catch (Exception ex)
        {
            return Task.FromResult(OperationResult.Fail($"Could not change the AutoRun policy: {ex.Message}", "REGISTRY_ERROR"));
        }
    }
}
