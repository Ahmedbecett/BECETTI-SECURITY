using Microsoft.Win32;
using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

/// <summary>
/// Identifies real installed browsers by filtering the same installed-apps
/// registry inventory Software Manager reads (no separate enumeration logic
/// to keep in sync), and reads the real Windows SmartScreen policy values
/// from the registry — the same values Windows Security's "App & browser
/// control" page reads.
/// </summary>
public sealed class BrowserSecurityService : IBrowserSecurityService
{
    private static readonly string[] KnownBrowserNames =
    {
        "Google Chrome", "Mozilla Firefox", "Microsoft Edge", "Opera", "Opera GX",
        "Brave", "Vivaldi", "Chromium", "Tor Browser", "Yandex Browser"
    };

    private readonly ISoftwareManagerService _software;

    public BrowserSecurityService(ISoftwareManagerService software)
    {
        _software = software;
    }

    public async Task<OperationResult<IReadOnlyList<BrowserInfo>>> GetInstalledBrowsersAsync()
    {
        var apps = await _software.GetInstalledAppsAsync().ConfigureAwait(false);
        if (!apps.Success || apps.Value is null)
            return OperationResult<IReadOnlyList<BrowserInfo>>.Fail(apps.Message, apps.ErrorCode);

        var browsers = apps.Value
            .Where(a => KnownBrowserNames.Any(b => a.Name.Contains(b, StringComparison.OrdinalIgnoreCase)))
            .Select(a => new BrowserInfo { Name = a.Name, Version = a.Version, Publisher = a.Publisher })
            .ToList();

        // Microsoft Edge ships with Windows and may not appear in the uninstall registry
        // inventory on every build; report it from the known system path rather than
        // silently omitting the browser almost every Windows PC actually has.
        if (!browsers.Any(b => b.Name.Contains("Edge", StringComparison.OrdinalIgnoreCase)) && EdgeIsInstalled())
            browsers.Add(new BrowserInfo { Name = "Microsoft Edge", Version = null, Publisher = "Microsoft Corporation" });

        return OperationResult<IReadOnlyList<BrowserInfo>>.Ok(
            browsers, $"{browsers.Count} browser(s) detected from the installed-apps inventory.");
    }

    private static bool EdgeIsInstalled()
    {
        try
        {
            return OperatingSystem.IsWindows() &&
                   (File.Exists(Environment.ExpandEnvironmentVariables(@"%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe")) ||
                    File.Exists(Environment.ExpandEnvironmentVariables(@"%ProgramFiles%\Microsoft\Edge\Application\msedge.exe")));
        }
        catch
        {
            return false;
        }
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    public Task<OperationResult<SmartScreenStatus>> GetSmartScreenStatusAsync()
    {
        if (!OperatingSystem.IsWindows())
            return Task.FromResult(OperationResult<SmartScreenStatus>.Fail("SmartScreen status requires Windows.", "UNSUPPORTED_OS"));

        try
        {
            bool? appsAndFiles = null;
            using (var key = Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"))
            {
                var value = key?.GetValue("SmartScreenEnabled") as string;
                if (!string.IsNullOrWhiteSpace(value))
                    appsAndFiles = !string.Equals(value, "Off", StringComparison.OrdinalIgnoreCase);
            }

            bool? edge = null;
            using (var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Edge"))
            {
                var value = key?.GetValue("SmartScreenEnabled");
                if (value is int i)
                    edge = i != 0;
            }

            return Task.FromResult(OperationResult<SmartScreenStatus>.Ok(
                new SmartScreenStatus { AppsAndFilesEnabled = appsAndFiles, EdgeSmartScreenEnabled = edge },
                "SmartScreen policy read from the registry."));
        }
        catch (Exception ex)
        {
            return Task.FromResult(OperationResult<SmartScreenStatus>.Fail($"Could not read SmartScreen policy: {ex.Message}", "REGISTRY_ERROR"));
        }
    }
}
