using Microsoft.Win32;
using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

/// <summary>
/// Reads and changes real Windows startup entries using the exact same
/// registry model Task Manager's "Startup apps" tab is built on: the Run key
/// holds the command, and a parallel StartupApproved key records whether the
/// user disabled it. This convention is undocumented by Microsoft but has
/// been stable and publicly reverse-engineered since Windows 8 (first DWORD
/// byte 0x02/0x06 = enabled, 0x03 = disabled by the user; a missing value
/// means enabled). BECETTI SECURITY never invents a numeric "impact" score —
/// Windows does not expose one through any stable public API.
/// </summary>
public sealed class StartupManagerService : IStartupManagerService
{
    private const string RunKeyPath = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string Wow64RunKeyPath = @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run";
    private const string ApprovedRunPath = @"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run";
    private const string ApprovedRun32Path = @"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32";

    // Registry.CurrentUser/LocalMachine are safe to reference on any OS (they just return a
    // handle wrapper); only the OpenSubKey/CreateSubKey calls below ever touch the real
    // registry, and those are reached only after the OperatingSystem.IsWindows() guard in
    // each public method. This pragma only silences the platform-compatibility analyzer
    // (CA1416) for that known-safe field initializer, not an actual behavior change.
#pragma warning disable CA1416
    private static readonly LocationDescriptor[] Locations =
    {
        new("HKCU", "This user", Registry.CurrentUser, RunKeyPath, ApprovedRunPath, RequiresElevation: false),
        new("HKLM", "All users", Registry.LocalMachine, RunKeyPath, ApprovedRunPath, RequiresElevation: true),
        new("HKLM32", "All users (32-bit)", Registry.LocalMachine, Wow64RunKeyPath, ApprovedRun32Path, RequiresElevation: true),
    };
#pragma warning restore CA1416

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    public Task<OperationResult<IReadOnlyList<StartupItemInfo>>> GetStartupItemsAsync()
    {
        if (!OperatingSystem.IsWindows())
            return Task.FromResult(OperationResult<IReadOnlyList<StartupItemInfo>>.Fail("Startup Manager is only available on Windows.", "UNSUPPORTED_OS"));

        var items = new List<StartupItemInfo>();
        foreach (var location in Locations)
        {
            try
            {
                using var runKey = location.Hive.OpenSubKey(location.RunPath);
                if (runKey is null)
                    continue;

                using var approvedKey = location.Hive.OpenSubKey(location.ApprovedPath);

                foreach (var valueName in runKey.GetValueNames())
                {
                    if (string.IsNullOrEmpty(valueName))
                        continue;

                    var command = runKey.GetValue(valueName)?.ToString() ?? string.Empty;
                    var approvedData = approvedKey?.GetValue(valueName) as byte[];

                    items.Add(new StartupItemInfo
                    {
                        Name = valueName,
                        Command = command,
                        LocationDisplay = location.DisplayName,
                        LocationKey = location.Key,
                        IsEnabled = ParseApprovedEnabled(approvedData),
                        RequiresElevationToChange = location.RequiresElevation
                    });
                }
            }
            catch
            {
                // A single unreadable hive/key (permissions, missing on this SKU) must not
                // fail the whole inventory — the other locations are still reported.
            }
        }

        return Task.FromResult(OperationResult<IReadOnlyList<StartupItemInfo>>.Ok(
            items.OrderBy(i => i.Name, StringComparer.OrdinalIgnoreCase).ToList(),
            "Startup items read from the Windows registry."));
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    public Task<OperationResult> SetEnabledAsync(StartupItemInfo item, bool enabled)
    {
        if (!OperatingSystem.IsWindows())
            return Task.FromResult(OperationResult.Fail("Startup Manager is only available on Windows.", "UNSUPPORTED_OS"));

        var location = Locations.FirstOrDefault(l => l.Key == item.LocationKey);
        if (location is null)
            return Task.FromResult(OperationResult.Fail("Unknown startup item location.", "UNKNOWN_LOCATION"));

        if (location.RequiresElevation && !ElevationHelper.IsElevated())
            return Task.FromResult(OperationResult.Fail("Changing this startup item requires an administrator. Restart BECETTI SECURITY as administrator from Settings.", "ELEVATION_REQUIRED"));

        try
        {
            using var approvedKey = location.Hive.CreateSubKey(location.ApprovedPath, writable: true);
            if (approvedKey is null)
                return Task.FromResult(OperationResult.Fail("Could not open the startup registry key for writing.", "REGISTRY_UNAVAILABLE"));

            approvedKey.SetValue(item.Name, BuildApprovedValue(enabled), RegistryValueKind.Binary);

            // Re-verify from the registry rather than assuming the write succeeded as asked.
            var confirmed = approvedKey.GetValue(item.Name) as byte[];
            if (ParseApprovedEnabled(confirmed) != enabled)
                return Task.FromResult(OperationResult.Fail("The startup item state could not be confirmed after the change.", "VERIFICATION_FAILED"));

            return Task.FromResult(OperationResult.Ok(enabled
                ? $"'{item.Name}' will now run at startup."
                : $"'{item.Name}' has been stopped from running at startup."));
        }
        catch (UnauthorizedAccessException)
        {
            return Task.FromResult(OperationResult.Fail("Access denied changing this startup item. Try running BECETTI SECURITY as administrator.", "ACCESS_DENIED"));
        }
        catch (Exception ex)
        {
            return Task.FromResult(OperationResult.Fail($"Could not change the startup item: {ex.Message}", "REGISTRY_ERROR"));
        }
    }

    /// <summary>
    /// Pure parser for the StartupApproved binary convention: first byte
    /// 0x02 or 0x06 means enabled, 0x03 means disabled by the user, and a
    /// missing value (no corresponding StartupApproved entry at all) also
    /// means enabled — Windows only records a value once someone has
    /// explicitly toggled Task Manager's switch.
    /// </summary>
    internal static bool ParseApprovedEnabled(byte[]? data)
    {
        if (data is null || data.Length == 0)
            return true;

        return data[0] != 0x03;
    }

    /// <summary>Builds the 12-byte StartupApproved value Task Manager itself writes.</summary>
    internal static byte[] BuildApprovedValue(bool enabled)
    {
        var value = new byte[12];
        if (enabled)
        {
            value[0] = 0x02;
        }
        else
        {
            value[0] = 0x03;
            var fileTime = BitConverter.GetBytes(DateTime.UtcNow.ToFileTimeUtc());
            Array.Copy(fileTime, 0, value, 4, 8);
        }

        return value;
    }

    private sealed record LocationDescriptor(string Key, string DisplayName, RegistryKey Hive, string RunPath, string ApprovedPath, bool RequiresElevation);
}
