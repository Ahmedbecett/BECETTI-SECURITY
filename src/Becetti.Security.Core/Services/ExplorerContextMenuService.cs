using Becetti.Security.Core.Models;
using Microsoft.Win32;

namespace Becetti.Security.Core.Services;

/// <summary>
/// Real Windows Explorer Right-Click Context Menu integration ("Scan with BECETTI YARA")
/// registered per-user in HKCU\Software\Classes (no Administrator elevation required).
/// Supports registering, verifying, and cleanly unregistering for both files and folders.
/// </summary>
public interface IExplorerContextMenuService
{
    bool IsRegistered();
    OperationResult Register(string? appExecutablePath = null);
    OperationResult Unregister();
}

public sealed class ExplorerContextMenuService : IExplorerContextMenuService
{
    private const string DefaultFileShellPath = @"Software\Classes\*\shell\BecettiYaraScan";
    private const string DefaultDirShellPath = @"Software\Classes\Directory\shell\BecettiYaraScan";

    private readonly string _fileShellPath;
    private readonly string _dirShellPath;

    public ExplorerContextMenuService(
        string fileShellRegistryPath = DefaultFileShellPath,
        string directoryShellRegistryPath = DefaultDirShellPath)
    {
        _fileShellPath = fileShellRegistryPath;
        _dirShellPath = directoryShellRegistryPath;
    }

    public bool IsRegistered()
    {
        if (!OperatingSystem.IsWindows())
            return false;

        try
        {
            using var fileCmd = Registry.CurrentUser.OpenSubKey($@"{_fileShellPath}\command");
            using var dirCmd = Registry.CurrentUser.OpenSubKey($@"{_dirShellPath}\command");
            var fVal = fileCmd?.GetValue(string.Empty) as string;
            var dVal = dirCmd?.GetValue(string.Empty) as string;
            return !string.IsNullOrWhiteSpace(fVal) && !string.IsNullOrWhiteSpace(dVal);
        }
        catch
        {
            return false;
        }
    }

    public OperationResult Register(string? appExecutablePath = null)
    {
        if (!OperatingSystem.IsWindows())
            return OperationResult.Fail("Windows Explorer context menu integration is only available on Windows.", "UNSUPPORTED_OS");

        var exePath = string.IsNullOrWhiteSpace(appExecutablePath)
            ? Environment.ProcessPath
            : appExecutablePath;

        if (string.IsNullOrWhiteSpace(exePath))
            return OperationResult.Fail("Could not resolve BECETTI SECURITY executable path.", "EXE_NOT_FOUND");

        try
        {
            WriteVerb(_fileShellPath, exePath);
            WriteVerb(_dirShellPath, exePath);

            return IsRegistered()
                ? OperationResult.Ok("Registered 'Scan with BECETTI YARA' in Windows Explorer right-click menu.")
                : OperationResult.Fail("Registry write could not be verified.", "VERIFY_FAILED");
        }
        catch (Exception ex)
        {
            return OperationResult.Fail($"Could not register Explorer context menu: {ex.Message}", "REGISTRY_ERROR");
        }
    }

    public OperationResult Unregister()
    {
        if (!OperatingSystem.IsWindows())
            return OperationResult.Fail("Windows Explorer context menu integration is only available on Windows.", "UNSUPPORTED_OS");

        try
        {
            Registry.CurrentUser.DeleteSubKeyTree(_fileShellPath, throwOnMissingSubKey: false);
            Registry.CurrentUser.DeleteSubKeyTree(_dirShellPath, throwOnMissingSubKey: false);
            return OperationResult.Ok("Removed 'Scan with BECETTI YARA' from Windows Explorer right-click menu.");
        }
        catch (Exception ex)
        {
            return OperationResult.Fail($"Could not remove Explorer context menu: {ex.Message}", "REGISTRY_ERROR");
        }
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static void WriteVerb(string keyPath, string exePath)
    {
        using var verbKey = Registry.CurrentUser.CreateSubKey(keyPath);
        verbKey.SetValue(string.Empty, "Scan with BECETTI YARA");
        verbKey.SetValue("Icon", $"\"{exePath}\",0");

        using var cmdKey = verbKey.CreateSubKey("command");
        cmdKey.SetValue(string.Empty, $"\"{exePath}\" --yara-scan \"%1\"");
    }
}
