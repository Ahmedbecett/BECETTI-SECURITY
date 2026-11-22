using System.Management;
using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

/// <summary>
/// Queries the real Win32_PnPSignedDriver WMI class — the official inventory
/// Device Manager itself reads — for every installed device driver's name,
/// manufacturer, version, date and digital-signature state.
/// </summary>
public sealed class DriverMonitorService : IDriverMonitorService
{
    public Task<OperationResult<IReadOnlyList<DriverInfo>>> GetDriversAsync() =>
        Task.Run(() => GetDrivers());

    private static OperationResult<IReadOnlyList<DriverInfo>> GetDrivers()
    {
        if (!OperatingSystem.IsWindows())
            return OperationResult<IReadOnlyList<DriverInfo>>.Fail("Driver Monitor is only available on Windows.", "UNSUPPORTED_OS");

        try
        {
            var drivers = new List<DriverInfo>();
            using var searcher = new ManagementObjectSearcher(
                "SELECT DeviceName, DeviceClass, Manufacturer, DriverVersion, DriverDate, IsSigned FROM Win32_PnPSignedDriver");

            foreach (ManagementBaseObject result in searcher.Get())
            {
                using (result)
                {
                    var deviceName = result["DeviceName"] as string;
                    if (string.IsNullOrWhiteSpace(deviceName))
                        continue;

                    drivers.Add(new DriverInfo
                    {
                        DeviceName = deviceName,
                        DeviceClass = result["DeviceClass"] as string,
                        Manufacturer = result["Manufacturer"] as string,
                        DriverVersion = result["DriverVersion"] as string,
                        DriverDate = ParseWmiDate(result["DriverDate"] as string),
                        IsSigned = result["IsSigned"] is bool signed && signed
                    });
                }
            }

            return OperationResult<IReadOnlyList<DriverInfo>>.Ok(
                drivers.OrderBy(d => d.DeviceClass ?? string.Empty, StringComparer.OrdinalIgnoreCase)
                       .ThenBy(d => d.DeviceName, StringComparer.OrdinalIgnoreCase)
                       .ToList(),
                $"{drivers.Count} installed driver(s) read from WMI (Win32_PnPSignedDriver).");
        }
        catch (Exception ex)
        {
            return OperationResult<IReadOnlyList<DriverInfo>>.Fail($"Could not read the driver inventory: {ex.Message}", "WMI_ERROR");
        }
    }

    internal static DateTimeOffset? ParseWmiDate(string? wmiDate)
    {
        if (string.IsNullOrWhiteSpace(wmiDate))
            return null;

        try
        {
            return new DateTimeOffset(ManagementDateTimeConverter.ToDateTime(wmiDate));
        }
        catch
        {
            return null;
        }
    }
}
