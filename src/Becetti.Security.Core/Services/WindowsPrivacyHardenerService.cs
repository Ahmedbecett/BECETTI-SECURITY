using System.Runtime.Versioning;
using Becetti.Security.Core.Models;
using Microsoft.Win32;

namespace Becetti.Security.Core.Services;

public interface IWindowsPrivacyHardenerService
{
    Task<OperationResult<PrivacyHardeningReport>> AuditPrivacyControlsAsync(CancellationToken ct = default);
    Task<OperationResult<string>> SetControlHardenedAsync(string controlId, bool harden, CancellationToken ct = default);
    Task<OperationResult<string>> HardenAllRecommendedAsync(CancellationToken ct = default);
}

/// <summary>
/// Real Windows Privacy &amp; Anti-Telemetry Hardener:
/// reads and toggles 6 real, fully reversible Windows Registry privacy controls
/// (Advertising ID, App Launch Tracking, Tailored Diagnostic Experiences,
/// Windows Error Reporting, Clipboard Cloud Sync, and Activity History Publishing).
/// Zero simulation, zero CA1416 warnings.
/// </summary>
public sealed class WindowsPrivacyHardenerService : IWindowsPrivacyHardenerService
{
    public async Task<OperationResult<PrivacyHardeningReport>> AuditPrivacyControlsAsync(CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
            return OperationResult<PrivacyHardeningReport>.Fail("Windows Privacy Hardener requires Windows.", "UNSUPPORTED_OS");

        var controls = new List<PrivacyControlItem>();

        await Task.Run(() =>
        {
            if (!OperatingSystem.IsWindows())
                return;
            controls.Add(ReadAdvertisingId());
            controls.Add(ReadAppLaunchTracking());
            controls.Add(ReadTailoredExperiences());
            controls.Add(ReadErrorReporting());
            controls.Add(ReadCloudClipboard());
            controls.Add(ReadActivityHistory());
        }, ct).ConfigureAwait(false);

        int hardened = controls.Count(c => c.IsHardened);
        var report = new PrivacyHardeningReport
        {
            AuditedAt = DateTimeOffset.UtcNow,
            HardenedCount = hardened,
            TotalCount = controls.Count,
            Controls = controls
        };

        return OperationResult<PrivacyHardeningReport>.Ok(
            report,
            $"Windows Privacy Score: {report.PrivacyScorePercent}% ({hardened}/{controls.Count} controls hardened).");
    }

    public async Task<OperationResult<string>> SetControlHardenedAsync(string controlId, bool harden, CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
            return OperationResult<string>.Fail("Windows Privacy Hardener requires Windows.", "UNSUPPORTED_OS");

        return await Task.Run(() =>
        {
            if (!OperatingSystem.IsWindows())
                return OperationResult<string>.Fail("Windows required.", "UNSUPPORTED_OS");

            try
            {
                switch ((controlId ?? string.Empty).Trim().ToLowerInvariant())
                {
                    case "advertising_id":
                        WriteHkcuDword("Software\\Microsoft\\Windows\\CurrentVersion\\AdvertisingInfo", "Enabled", harden ? 0 : 1);
                        return OperationResult<string>.Ok("advertising_id", harden ? "Disabled Windows Advertising ID." : "Re-enabled Windows Advertising ID.");

                    case "app_launch_tracking":
                        WriteHkcuDword("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced", "Start_TrackProgs", harden ? 0 : 1);
                        return OperationResult<string>.Ok("app_launch_tracking", harden ? "Disabled Start Menu app launch tracking." : "Re-enabled Start Menu app launch tracking.");

                    case "tailored_experiences":
                        WriteHkcuDword("Software\\Microsoft\\Windows\\CurrentVersion\\Privacy", "TailoredExperiencesWithDiagnosticDataEnabled", harden ? 0 : 1);
                        return OperationResult<string>.Ok("tailored_experiences", harden ? "Disabled tailored diagnostic experiences." : "Re-enabled tailored diagnostic experiences.");

                    case "error_reporting":
                        WriteHkcuDword("Software\\Microsoft\\Windows\\Windows Error Reporting", "Disabled", harden ? 1 : 0);
                        return OperationResult<string>.Ok("error_reporting", harden ? "Disabled automatic Windows Error Reporting uploads." : "Re-enabled Windows Error Reporting.");

                    case "cloud_clipboard":
                        WriteHkcuDword("Software\\Microsoft\\Clipboard", "EnableCloudClipboard", harden ? 0 : 1);
                        return OperationResult<string>.Ok("cloud_clipboard", harden ? "Disabled Cloud Clipboard synchronization." : "Re-enabled Cloud Clipboard sync.");

                    case "activity_history":
                        using (var key = Registry.LocalMachine.CreateSubKey("SOFTWARE\\Policies\\Microsoft\\Windows\\System", writable: true))
                        {
                            if (key is null)
                                return OperationResult<string>.Fail("Administrator privileges required to modify Activity History policy.", "ADMIN_REQUIRED");
                            key.SetValue("PublishUserActivities", harden ? 0 : 1, RegistryValueKind.DWord);
                        }
                        return OperationResult<string>.Ok("activity_history", harden ? "Disabled Windows Activity History publishing." : "Re-enabled Activity History publishing.");

                    default:
                        return OperationResult<string>.Fail($"Unknown privacy control '{controlId}'.", "UNKNOWN_CONTROL");
                }
            }
            catch (UnauthorizedAccessException)
            {
                return OperationResult<string>.Fail("Administrator privileges required for this machine-wide privacy policy.", "ADMIN_REQUIRED");
            }
            catch (Exception ex)
            {
                return OperationResult<string>.Fail($"Privacy update failed: {ex.Message}", "PRIVACY_ERROR");
            }
        }, ct).ConfigureAwait(false);
    }

    public async Task<OperationResult<string>> HardenAllRecommendedAsync(CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
            return OperationResult<string>.Fail("Windows Privacy Hardener requires Windows.", "UNSUPPORTED_OS");

        string[] userControls = { "advertising_id", "app_launch_tracking", "tailored_experiences", "error_reporting", "cloud_clipboard" };
        int applied = 0;
        foreach (var id in userControls)
        {
            var r = await SetControlHardenedAsync(id, true, ct).ConfigureAwait(false);
            if (r.Success) applied++;
        }

        var adminRes = await SetControlHardenedAsync("activity_history", true, ct).ConfigureAwait(false);
        if (adminRes.Success) applied++;

        return OperationResult<string>.Ok(
            $"{applied}/6 hardened",
            $"Applied {applied}/6 Windows Privacy & Anti-Telemetry hardening controls.");
    }

    [SupportedOSPlatform("windows")]
    private static void WriteHkcuDword(string subKey, string valueName, int value)
    {
        using var key = Registry.CurrentUser.CreateSubKey(subKey, writable: true);
        key?.SetValue(valueName, value, RegistryValueKind.DWord);
    }

    [SupportedOSPlatform("windows")]
    private static PrivacyControlItem ReadAdvertisingId()
    {
        using var key = Registry.CurrentUser.OpenSubKey("Software\\Microsoft\\Windows\\CurrentVersion\\AdvertisingInfo");
        int val = Convert.ToInt32(key?.GetValue("Enabled") ?? 1);
        bool hardened = val == 0;
        return new PrivacyControlItem
        {
            Id = "advertising_id",
            Title = "Windows Advertising ID",
            Description = "Stops apps from tracking your behavior across apps using your Windows advertising identifier.",
            IsHardened = hardened,
            CurrentState = hardened ? "Disabled (Private)" : "Enabled (Tracking Active)",
            RegistryLocation = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\AdvertisingInfo\\Enabled"
        };
    }

    [SupportedOSPlatform("windows")]
    private static PrivacyControlItem ReadAppLaunchTracking()
    {
        using var key = Registry.CurrentUser.OpenSubKey("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced");
        int val = Convert.ToInt32(key?.GetValue("Start_TrackProgs") ?? 1);
        bool hardened = val == 0;
        return new PrivacyControlItem
        {
            Id = "app_launch_tracking",
            Title = "Start Menu App Launch Tracking",
            Description = "Prevents Windows from logging every application launch for personalized recommendations.",
            IsHardened = hardened,
            CurrentState = hardened ? "Disabled (Private)" : "Enabled",
            RegistryLocation = "HKCU\\...\\Explorer\\Advanced\\Start_TrackProgs"
        };
    }

    [SupportedOSPlatform("windows")]
    private static PrivacyControlItem ReadTailoredExperiences()
    {
        using var key = Registry.CurrentUser.OpenSubKey("Software\\Microsoft\\Windows\\CurrentVersion\\Privacy");
        int val = Convert.ToInt32(key?.GetValue("TailoredExperiencesWithDiagnosticDataEnabled") ?? 1);
        bool hardened = val == 0;
        return new PrivacyControlItem
        {
            Id = "tailored_experiences",
            Title = "Tailored Diagnostic Experiences",
            Description = "Stops Microsoft from using diagnostic telemetry to display personalized tips and ads.",
            IsHardened = hardened,
            CurrentState = hardened ? "Disabled (Private)" : "Enabled",
            RegistryLocation = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Privacy"
        };
    }

    [SupportedOSPlatform("windows")]
    private static PrivacyControlItem ReadErrorReporting()
    {
        using var key = Registry.CurrentUser.OpenSubKey("Software\\Microsoft\\Windows\\Windows Error Reporting");
        int disabled = Convert.ToInt32(key?.GetValue("Disabled") ?? 0);
        bool hardened = disabled == 1;
        return new PrivacyControlItem
        {
            Id = "error_reporting",
            Title = "Windows Error Reporting (WER) Uploads",
            Description = "Prevents automatic crash dump uploads that may contain sensitive memory fragments.",
            IsHardened = hardened,
            CurrentState = hardened ? "Disabled (Private)" : "Active",
            RegistryLocation = "HKCU\\Software\\Microsoft\\Windows\\Windows Error Reporting\\Disabled"
        };
    }

    [SupportedOSPlatform("windows")]
    private static PrivacyControlItem ReadCloudClipboard()
    {
        using var key = Registry.CurrentUser.OpenSubKey("Software\\Microsoft\\Clipboard");
        int enabled = Convert.ToInt32(key?.GetValue("EnableCloudClipboard") ?? 0);
        bool hardened = enabled == 0;
        return new PrivacyControlItem
        {
            Id = "cloud_clipboard",
            Title = "Cloud Clipboard Sync",
            Description = "Keeps copied passwords, crypto addresses, and documents strictly local to this PC.",
            IsHardened = hardened,
            CurrentState = hardened ? "Local Only (Private)" : "Cloud Sync Enabled",
            RegistryLocation = "HKCU\\Software\\Microsoft\\Clipboard\\EnableCloudClipboard"
        };
    }

    [SupportedOSPlatform("windows")]
    private static PrivacyControlItem ReadActivityHistory()
    {
        using var key = Registry.LocalMachine.OpenSubKey("SOFTWARE\\Policies\\Microsoft\\Windows\\System");
        var raw = key?.GetValue("PublishUserActivities");
        bool hardened = raw is not null && Convert.ToInt32(raw) == 0;
        return new PrivacyControlItem
        {
            Id = "activity_history",
            Title = "Activity History Publishing (Admin Policy)",
            Description = "Blocks Windows from publishing local user activity history to Microsoft cloud services.",
            IsHardened = hardened,
            CurrentState = hardened ? "Blocked by Policy" : "Default (Allowed)",
            RegistryLocation = "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System\\PublishUserActivities"
        };
    }
}
