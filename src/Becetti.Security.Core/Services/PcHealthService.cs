using System.Runtime.InteropServices;
using System.ServiceProcess;
using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

/// <summary>
/// Reads live CPU/RAM/disk/service health directly from official Win32 and
/// .NET APIs. CPU usage is measured by sampling GetSystemTimes twice a short
/// interval apart (the same technique Task Manager itself is built on) -
/// never a fabricated or fixed number. A failure anywhere (API unavailable,
/// access denied to a service) degrades that one field to "unavailable"
/// rather than failing the whole snapshot or inventing a value.
/// </summary>
public sealed class PcHealthService : IPcHealthService
{
    private static readonly TimeSpan CpuSampleInterval = TimeSpan.FromMilliseconds(400);

    private static readonly (string ServiceName, string FriendlyName)[] SecurityRelevantServices =
    {
        ("WinDefend", "Microsoft Defender Antivirus Service"),
        ("MpsSvc", "Windows Defender Firewall"),
        ("wuauserv", "Windows Update"),
        ("BITS", "Background Intelligent Transfer Service"),
        ("Schedule", "Task Scheduler"),
        ("SecurityHealthService", "Windows Security Center Service")
    };

    public async Task<OperationResult<PcHealthSnapshot>> GetSnapshotAsync(CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
            return OperationResult<PcHealthSnapshot>.Fail("PC health checks are only available on Windows.", "UNSUPPORTED_OS");

        var performance = await ReadPerformanceAsync(ct).ConfigureAwait(false);
        var disks = ReadDisks();
        var services = ReadServices();

        var snapshot = new PcHealthSnapshot
        {
            Performance = performance,
            Disks = disks,
            Services = services,
            CheckedAt = DateTimeOffset.Now
        };

        return OperationResult<PcHealthSnapshot>.Ok(snapshot, "PC health read from live Windows APIs.");
    }

    private static async Task<PerformanceSnapshot> ReadPerformanceAsync(CancellationToken ct)
    {
        try
        {
            if (!TryGetSystemTimes(out var idle1, out var kernel1, out var user1))
                return new PerformanceSnapshot { Available = false };

            await Task.Delay(CpuSampleInterval, ct).ConfigureAwait(false);

            if (!TryGetSystemTimes(out var idle2, out var kernel2, out var user2))
                return new PerformanceSnapshot { Available = false };

            var idleDelta = ToLong(idle2) - ToLong(idle1);
            var kernelDelta = ToLong(kernel2) - ToLong(kernel1);
            var userDelta = ToLong(user2) - ToLong(user1);
            var totalDelta = kernelDelta + userDelta; // kernel time already includes idle time on Windows

            var cpuUsage = totalDelta > 0
                ? Math.Clamp(100.0 * (totalDelta - idleDelta) / totalDelta, 0, 100)
                : 0;

            var memStatus = new MEMORYSTATUSEX { dwLength = (uint)Marshal.SizeOf<MEMORYSTATUSEX>() };
            var hasMemory = GlobalMemoryStatusEx(ref memStatus);

            return new PerformanceSnapshot
            {
                Available = true,
                CpuUsagePercent = Math.Round(cpuUsage, 1),
                TotalPhysicalMemoryBytes = hasMemory ? memStatus.ullTotalPhys : 0,
                AvailablePhysicalMemoryBytes = hasMemory ? memStatus.ullAvailPhys : 0,
                MemoryLoadPercent = hasMemory ? memStatus.dwMemoryLoad : 0
            };
        }
        catch
        {
            // A genuinely unavailable API must degrade this field, never crash the page or fake a number.
            return new PerformanceSnapshot { Available = false };
        }
    }

    private static IReadOnlyList<DiskHealthInfo> ReadDisks()
    {
        var disks = new List<DiskHealthInfo>();
        try
        {
            foreach (var drive in DriveInfo.GetDrives())
            {
                if (drive.DriveType != DriveType.Fixed || !drive.IsReady)
                    continue;

                try
                {
                    disks.Add(new DiskHealthInfo
                    {
                        Name = drive.Name,
                        VolumeLabel = SafeVolumeLabel(drive),
                        FreeBytes = drive.AvailableFreeSpace,
                        TotalBytes = drive.TotalSize
                    });
                }
                catch
                {
                    // A single inaccessible/unready drive must not drop the rest.
                }
            }
        }
        catch
        {
            // DriveInfo.GetDrives() itself failing leaves the list empty rather than throwing.
        }

        return disks;
    }

    private static string SafeVolumeLabel(DriveInfo drive)
    {
        try
        {
            return string.IsNullOrWhiteSpace(drive.VolumeLabel) ? "Local Disk" : drive.VolumeLabel;
        }
        catch
        {
            return "Local Disk";
        }
    }

    private static IReadOnlyList<ServiceHealthInfo> ReadServices()
    {
        var results = new List<ServiceHealthInfo>();
        foreach (var (serviceName, friendlyName) in SecurityRelevantServices)
        {
            try
            {
                using var controller = new ServiceController(serviceName);
                var status = controller.Status; // throws InvalidOperationException if the service does not exist on this device
                results.Add(new ServiceHealthInfo
                {
                    ServiceName = serviceName,
                    DisplayName = string.IsNullOrWhiteSpace(controller.DisplayName) ? friendlyName : controller.DisplayName,
                    Status = status.ToString(),
                    IsRunning = status == ServiceControllerStatus.Running,
                    IsSecurityRelevant = true
                });
            }
            catch
            {
                // Service not present on this edition/SKU of Windows, or access denied:
                // report it as unknown rather than guessing or omitting it silently.
                results.Add(new ServiceHealthInfo
                {
                    ServiceName = serviceName,
                    DisplayName = friendlyName,
                    Status = "Unknown",
                    IsRunning = false,
                    IsSecurityRelevant = true
                });
            }
        }

        return results;
    }

    private static long ToLong(FILETIME ft) => ((long)ft.dwHighDateTime << 32) | (uint)ft.dwLowDateTime;

    private static bool TryGetSystemTimes(out FILETIME idle, out FILETIME kernel, out FILETIME user)
    {
        idle = default;
        kernel = default;
        user = default;
        return OperatingSystem.IsWindows() && GetSystemTimes(out idle, out kernel, out user);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FILETIME
    {
        public uint dwLowDateTime;
        public uint dwHighDateTime;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MEMORYSTATUSEX
    {
        public uint dwLength;
        public uint dwMemoryLoad;
        public ulong ullTotalPhys;
        public ulong ullAvailPhys;
        public ulong ullTotalPageFile;
        public ulong ullAvailPageFile;
        public ulong ullTotalVirtual;
        public ulong ullAvailVirtual;
        public ulong ullAvailExtendedVirtual;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetSystemTimes(out FILETIME lpIdleTime, out FILETIME lpKernelTime, out FILETIME lpUserTime);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GlobalMemoryStatusEx(ref MEMORYSTATUSEX lpBuffer);
}
