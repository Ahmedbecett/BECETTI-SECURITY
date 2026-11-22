using System.Diagnostics;
using System.Globalization;
using Microsoft.Win32;
using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

/// <summary>
/// Reads the real "installed programs" registry inventory — the exact same
/// source Settings &gt; Apps &gt; Installed apps uses — and, on request,
/// launches an application's own real uninstaller. BECETTI SECURITY never
/// removes a program itself; it only starts the vendor's own UninstallString,
/// which shows its own native confirmation/progress UI.
/// </summary>
public sealed class SoftwareManagerService : ISoftwareManagerService
{
    // Registry.LocalMachine/CurrentUser are safe to reference on any OS (they just return a
    // handle wrapper); only OpenSubKey/GetSubKeyNames/GetValue below ever touch the real
    // registry, reached only after the OperatingSystem.IsWindows() guard in
    // GetInstalledAppsAsync. This pragma only silences the platform-compatibility analyzer
    // (CA1416) for that known-safe field initializer, not an actual behavior change.
#pragma warning disable CA1416
    private static readonly (RegistryKey Hive, string Path)[] UninstallKeys =
    {
        (Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
        (Registry.LocalMachine, @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        (Registry.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
    };
#pragma warning restore CA1416

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    public Task<OperationResult<IReadOnlyList<InstalledAppInfo>>> GetInstalledAppsAsync()
    {
        if (!OperatingSystem.IsWindows())
            return Task.FromResult(OperationResult<IReadOnlyList<InstalledAppInfo>>.Fail("Software Manager is only available on Windows.", "UNSUPPORTED_OS"));

        var apps = new List<InstalledAppInfo>();
        var seenNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var (hive, path) in UninstallKeys)
        {
            try
            {
                using var uninstallRoot = hive.OpenSubKey(path);
                if (uninstallRoot is null)
                    continue;

                foreach (var subKeyName in uninstallRoot.GetSubKeyNames())
                {
                    try
                    {
                        using var entry = uninstallRoot.OpenSubKey(subKeyName);
                        var app = ReadEntry(entry);
                        if (app is null)
                            continue;

                        // The same product can legitimately appear in more than one hive view
                        // (e.g. 32-bit and 64-bit registry views); keep only the first seen.
                        if (seenNames.Add(app.Name))
                            apps.Add(app);
                    }
                    catch
                    {
                        // One unreadable entry must not drop the rest of the inventory.
                    }
                }
            }
            catch
            {
                // A whole key being unreadable (permissions, missing on this SKU) still
                // leaves the other locations available.
            }
        }

        return Task.FromResult(OperationResult<IReadOnlyList<InstalledAppInfo>>.Ok(
            apps.OrderBy(a => a.Name, StringComparer.OrdinalIgnoreCase).ToList(),
            $"{apps.Count} installed application(s) read from the Windows registry."));
    }

    public OperationResult LaunchUninstaller(InstalledAppInfo app)
    {
        if (!OperatingSystem.IsWindows())
            return OperationResult.Fail("Software Manager is only available on Windows.", "UNSUPPORTED_OS");

        if (string.IsNullOrWhiteSpace(app.UninstallCommand))
            return OperationResult.Fail($"'{app.Name}' does not report an uninstaller.", "NO_UNINSTALLER");

        try
        {
            // Run through cmd.exe so quoted paths and extra arguments in the vendor's own
            // UninstallString are interpreted the same way Settings > Apps itself launches
            // it. UseShellExecute lets the uninstaller request its own UAC elevation.
            var startInfo = new ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = $"/c {app.UninstallCommand}",
                UseShellExecute = true
            };
            Process.Start(startInfo);
            return OperationResult.Ok($"Launched the uninstaller for '{app.Name}'. Follow its own prompts to finish removing it.");
        }
        catch (Exception ex)
        {
            return OperationResult.Fail($"Could not launch the uninstaller for '{app.Name}': {ex.Message}", "LAUNCH_FAILED");
        }
    }

    // Only ever called from GetInstalledAppsAsync, which already guards on
    // OperatingSystem.IsWindows() before reaching here.
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static InstalledAppInfo? ReadEntry(RegistryKey? entry)
    {
        if (entry is null)
            return null;

        var displayName = entry.GetValue("DisplayName") as string;
        if (string.IsNullOrWhiteSpace(displayName))
            return null;

        // SystemComponent=1 marks shared runtime/component entries (e.g. a redistributable)
        // that Settings > Apps itself hides from the user-facing list.
        if (entry.GetValue("SystemComponent") is int systemComponent && systemComponent == 1)
            return null;

        // ParentKeyName marks a patch/update entry attached to a parent product, not a
        // standalone installed application.
        if (entry.GetValue("ParentKeyName") is string parent && !string.IsNullOrWhiteSpace(parent))
            return null;

        return new InstalledAppInfo
        {
            Name = displayName.Trim(),
            Version = entry.GetValue("DisplayVersion") as string,
            Publisher = entry.GetValue("Publisher") as string,
            InstallDate = ParseInstallDate(entry.GetValue("InstallDate") as string),
            UninstallCommand = entry.GetValue("UninstallString") as string
        };
    }

    internal static DateTimeOffset? ParseInstallDate(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw) || raw.Length != 8)
            return null;

        return DateTime.TryParseExact(raw, "yyyyMMdd", CultureInfo.InvariantCulture, DateTimeStyles.None, out var parsed)
            ? new DateTimeOffset(parsed)
            : null;
    }
}
