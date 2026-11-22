using System.Net;
using System.Net.NetworkInformation;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Principal;
using Becetti.Security.Core.Models;
using Microsoft.Win32;

namespace Becetti.Security.Core.Services;

/// <summary>
/// Device and network facts from real OS APIs. Registry values, drive info,
/// network interfaces, DNS and a real TLS handshake — nothing is invented.
/// </summary>
public sealed class SystemInfoService : ISystemInfoService
{
    private readonly IDefenderService _defender;

    public SystemInfoService(IDefenderService defender)
    {
        _defender = defender;
    }

    public Task<OperationResult<DeviceInfo>> GetDeviceInfoAsync(CancellationToken ct = default)
    {
        try
        {
            var osDescription = Environment.OSVersion.VersionString;
            var osBuild = Environment.OSVersion.Version.ToString();

            if (OperatingSystem.IsWindows())
            {
                using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
                var productName = key?.GetValue("ProductName") as string;
                var displayVersion = key?.GetValue("DisplayVersion") as string;
                var buildNumber = key?.GetValue("CurrentBuildNumber") as string;
                if (!string.IsNullOrWhiteSpace(productName))
                    osDescription = string.IsNullOrWhiteSpace(displayVersion) ? productName : $"{productName} {displayVersion}";
                if (!string.IsNullOrWhiteSpace(buildNumber))
                    osBuild = buildNumber;
            }

            var systemDrive = new DriveInfo(Path.GetPathRoot(Environment.SystemDirectory) ?? "C:\\");
            var defenderPath = _defender.FindMpCmdRun();

            var isAdmin = false;
            if (OperatingSystem.IsWindows())
            {
                using var identity = WindowsIdentity.GetCurrent();
                isAdmin = new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
            }

            var info = new DeviceInfo
            {
                DeviceName = Environment.MachineName,
                OsDescription = osDescription,
                OsBuild = osBuild,
                Architecture = Environment.Is64BitOperatingSystem ? "x64" : "x86",
                RuntimeVersion = Environment.Version.ToString(),
                DefenderInstalled = defenderPath is not null,
                DefenderPath = defenderPath,
                IsAdministrator = isAdmin,
                UacEnabled = ReadUacEnabled(),
                SystemDriveFreeBytes = systemDrive.AvailableFreeSpace,
                SystemDriveTotalBytes = systemDrive.TotalSize
            };

            return Task.FromResult(OperationResult<DeviceInfo>.Ok(info, "Device information read from the OS."));
        }
        catch (Exception ex)
        {
            return Task.FromResult(OperationResult<DeviceInfo>.Fail($"Could not read device information: {ex.Message}", "SYSTEM_INFO_FAILED"));
        }
    }

    public async Task<OperationResult<NetworkCheckResult>> CheckNetworkAsync(string? apiBaseUrl, CancellationToken ct = default)
    {
        var networkAvailable = NetworkInterface.GetIsNetworkAvailable();
        string? activeAdapter = null;
        try
        {
            activeAdapter = NetworkInterface.GetAllNetworkInterfaces()
                .Where(n => n.OperationalStatus == OperationalStatus.Up && n.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                .Select(n => n.Name)
                .FirstOrDefault();
        }
        catch
        {
            activeAdapter = null;
        }

        var dnsOk = false;
        var tlsOk = false;
        string? tlsDetail = null;

        if (!string.IsNullOrWhiteSpace(apiBaseUrl) && Uri.TryCreate(apiBaseUrl, UriKind.Absolute, out var uri))
        {
            try
            {
                var entry = await Dns.GetHostEntryAsync(uri.Host, ct).ConfigureAwait(false);
                dnsOk = entry.AddressList.Length > 0;
            }
            catch (Exception ex)
            {
                tlsDetail = $"DNS resolution failed for {uri.Host}: {ex.Message}";
            }

            if (dnsOk)
            {
                try
                {
                    using var client = new TcpClient();
                    await client.ConnectAsync(uri.Host, uri.IsDefaultPort ? 443 : uri.Port, ct).ConfigureAwait(false);
                    using var stream = client.GetStream();
                    // Default certificate validation is used on purpose: BECETTI SECURITY
                    // never disables TLS verification.
                    using var ssl = new SslStream(stream, leaveInnerStreamOpen: false);
                    // SslStream has no AuthenticateAsClientAsync(string, CancellationToken) overload;
                    // the only overload that accepts a CancellationToken takes SslClientAuthenticationOptions.
                    var sslOptions = new SslClientAuthenticationOptions { TargetHost = uri.Host };
                    await ssl.AuthenticateAsClientAsync(sslOptions, ct).ConfigureAwait(false);
                    tlsOk = ssl.IsAuthenticated;
                    tlsDetail = tlsOk
                        ? $"TLS handshake succeeded with {uri.Host} (protocol {ssl.SslProtocol})."
                        : $"TLS handshake did not authenticate with {uri.Host}.";
                }
                catch (Exception ex)
                {
                    tlsDetail = $"TLS handshake failed for {uri.Host}: {ex.Message}";
                }
            }
        }
        else
        {
            tlsDetail = "No cloud API URL configured, so no TLS target was tested.";
        }

        var result = new NetworkCheckResult
        {
            NetworkAvailable = networkAvailable,
            ActiveAdapter = activeAdapter,
            DnsResolvable = dnsOk,
            TlsHandshakeOk = tlsOk,
            TlsDetail = tlsDetail,
            CheckedAt = DateTimeOffset.Now
        };

        return OperationResult<NetworkCheckResult>.Ok(result, "Network checks completed.");
    }

    private static bool ReadUacEnabled()
    {
        if (!OperatingSystem.IsWindows())
            return false;

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System");
            var value = key?.GetValue("EnableLUA");
            return value is int enabled && enabled == 1;
        }
        catch
        {
            return false;
        }
    }

    public Task<OperationResult<IReadOnlyList<PrivacyPermissionInfo>>> GetPrivacyPermissionsAsync(CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
            return Task.FromResult(OperationResult<IReadOnlyList<PrivacyPermissionInfo>>.Fail("Privacy permission checks are only available on Windows.", "UNSUPPORTED_OS"));

        IReadOnlyList<PrivacyPermissionInfo> permissions = new List<PrivacyPermissionInfo>
        {
            new() { Name = "Camera", Allowed = ReadGlobalCapabilityConsent("webcam") },
            new() { Name = "Microphone", Allowed = ReadGlobalCapabilityConsent("microphone") },
            new() { Name = "Location", Allowed = ReadGlobalCapabilityConsent("location") },
        };

        return Task.FromResult(OperationResult<IReadOnlyList<PrivacyPermissionInfo>>.Ok(
            permissions, "Privacy permission switches read from Windows (device-wide state)."));
    }

    /// <summary>
    /// Reads the device-wide "allow apps to access your &lt;capability&gt;" master
    /// switch from the real CapabilityAccessManager ConsentStore key. This is the
    /// same switch Settings &gt; Privacy &amp; security itself reads/writes; it is
    /// not a per-app permission list.
    /// </summary>
    // Only ever called from GetPrivacyPermissionsAsync, which already guards on
    // OperatingSystem.IsWindows() before reaching here.
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static bool? ReadGlobalCapabilityConsent(string capability)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                $@"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\{capability}");
            return (key?.GetValue("Value") as string) switch
            {
                "Allow" => true,
                "Deny" => false,
                _ => null
            };
        }
        catch
        {
            return null;
        }
    }
}
