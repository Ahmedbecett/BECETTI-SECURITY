using System.Runtime.Versioning;
using Becetti.Security.Core.Models;
using Microsoft.Win32;

namespace Becetti.Security.Core.Services;

public interface ICameraMicAuditorService
{
    Task<OperationResult<CameraMicAuditReport>> AuditAsync(CancellationToken ct = default);
}

/// <summary>
/// Real Windows Camera & Microphone Privacy Access Auditor:
/// reads HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore
/// (both packaged UWP/MSIX apps and NonPackaged Win32 apps) to identify apps actively using
/// the webcam or microphone right now (LastUsedTimeStart > 0 && LastUsedTimeStop == 0)
/// and recent historical access timestamps. Zero simulation.
/// </summary>
public sealed class CameraMicAuditorService : ICameraMicAuditorService
{
    private const string BaseKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore";

    public Task<OperationResult<CameraMicAuditReport>> AuditAsync(CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
            return Task.FromResult(OperationResult<CameraMicAuditReport>.Fail("Camera & Microphone auditing requires Windows.", "UNSUPPORTED_OS"));

        var entries = new List<DevicePrivacyAccessEntry>();

        ReadCapability("Camera", $@"{BaseKey}\webcam", entries);
        ReadCapability("Microphone", $@"{BaseKey}\microphone", entries);

        var sorted = entries
            .OrderByDescending(e => e.IsActiveNow)
            .ThenByDescending(e => e.LastUsedStart ?? DateTimeOffset.MinValue)
            .Take(100)
            .ToList();

        var report = new CameraMicAuditReport
        {
            AuditedAt = DateTimeOffset.UtcNow,
            ActiveCameraApps = sorted.Count(e => e.IsActiveNow && e.Capability == "Camera"),
            ActiveMicrophoneApps = sorted.Count(e => e.IsActiveNow && e.Capability == "Microphone"),
            Entries = sorted
        };

        var msg = (report.ActiveCameraApps > 0 || report.ActiveMicrophoneApps > 0)
            ? $"LIVE ACCESS DETECTED: {report.ActiveCameraApps} camera app(s), {report.ActiveMicrophoneApps} microphone app(s) active right now."
            : $"No active camera or microphone streams right now ({sorted.Count} historical app record(s) found).";

        return Task.FromResult(OperationResult<CameraMicAuditReport>.Ok(report, msg));
    }

    [SupportedOSPlatform("windows")]
    private static void ReadCapability(string capabilityName, string keyPath, List<DevicePrivacyAccessEntry> output)
    {
        try
        {
            using var root = Registry.CurrentUser.OpenSubKey(keyPath);
            if (root is null) return;

            foreach (var subName in root.GetSubKeyNames())
            {
                if (subName.Equals("NonPackaged", StringComparison.OrdinalIgnoreCase))
                {
                    using var np = root.OpenSubKey("NonPackaged");
                    if (np is null) continue;
                    foreach (var npSub in np.GetSubKeyNames())
                    {
                        using var appKey = np.OpenSubKey(npSub);
                        if (appKey is null) continue;
                        var decodedPath = npSub.Replace('#', '\\');
                        var friendly = Path.GetFileName(decodedPath);
                        if (string.IsNullOrWhiteSpace(friendly)) friendly = decodedPath;
                        AddIfRecorded(output, capabilityName, friendly, decodedPath, isPackaged: false, appKey);
                    }
                }
                else
                {
                    using var appKey = root.OpenSubKey(subName);
                    if (appKey is null) continue;
                    var friendly = subName.Split('_')[0];
                    AddIfRecorded(output, capabilityName, friendly, subName, isPackaged: true, appKey);
                }
            }
        }
        catch { }
    }

    [SupportedOSPlatform("windows")]
    private static void AddIfRecorded(
        List<DevicePrivacyAccessEntry> output,
        string capability,
        string appName,
        string identifier,
        bool isPackaged,
        RegistryKey key)
    {
        try
        {
            long startFt = Convert.ToInt64(key.GetValue("LastUsedTimeStart") ?? 0L);
            long stopFt = Convert.ToInt64(key.GetValue("LastUsedTimeStop") ?? 0L);

            if (startFt <= 0) return;

            DateTimeOffset? start = TryFromFileTime(startFt);
            DateTimeOffset? stop = stopFt > 0 ? TryFromFileTime(stopFt) : null;
            bool activeNow = startFt > 0 && stopFt == 0;

            output.Add(new DevicePrivacyAccessEntry
            {
                Capability = capability,
                AppName = appName,
                Identifier = identifier,
                IsPackaged = isPackaged,
                IsActiveNow = activeNow,
                LastUsedStart = start,
                LastUsedStop = stop
            });
        }
        catch { }
    }

    private static DateTimeOffset? TryFromFileTime(long ft)
    {
        try { return DateTimeOffset.FromFileTime(ft); }
        catch { return null; }
    }
}
