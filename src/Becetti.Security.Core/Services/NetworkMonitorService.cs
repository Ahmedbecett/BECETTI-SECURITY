using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Text.Json;
using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

/// <summary>
/// Network Monitor: real network adapters from .NET's own NetworkInterface
/// API, and real active TCP connections / listening ports from
/// Get-NetTCPConnection (the same cmdlet Resource Monitor's Network tab is
/// built on). BECETTI SECURITY draws no "malicious" conclusion of its own —
/// it shows Windows' own verified connection list and process ownership.
/// </summary>
public sealed class NetworkMonitorService : INetworkMonitorService
{
    private static readonly TimeSpan QueryTimeout = TimeSpan.FromSeconds(30);

    public Task<OperationResult<IReadOnlyList<NetworkAdapterInfo>>> GetAdaptersAsync() =>
        Task.Run(() => GetAdapters());

    private static OperationResult<IReadOnlyList<NetworkAdapterInfo>> GetAdapters()
    {
        try
        {
            var adapters = NetworkInterface.GetAllNetworkInterfaces()
                .Select(ToAdapterInfo)
                .OrderByDescending(a => a.IsUp)
                .ThenBy(a => a.Name, StringComparer.OrdinalIgnoreCase)
                .ToList();

            return OperationResult<IReadOnlyList<NetworkAdapterInfo>>.Ok(
                adapters, $"{adapters.Count} network adapter(s) read from Windows.");
        }
        catch (Exception ex)
        {
            return OperationResult<IReadOnlyList<NetworkAdapterInfo>>.Fail(
                $"Could not list network adapters: {ex.Message}", "ADAPTER_ENUM_ERROR");
        }
    }

    internal static NetworkAdapterInfo ToAdapterInfo(NetworkInterface nic)
    {
        var ipv4 = Array.Empty<string>();
        long? speed = null;
        try
        {
            ipv4 = nic.GetIPProperties().UnicastAddresses
                .Where(a => a.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                .Select(a => a.Address.ToString())
                .ToArray();
        }
        catch
        {
            // Some adapters (virtual, disabled) throw reading IP properties; an empty
            // address list is the honest result rather than a guessed one.
        }

        try
        {
            speed = nic.Speed >= 0 ? nic.Speed : null;
        }
        catch
        {
            speed = null;
        }

        string? mac = null;
        try
        {
            var bytes = nic.GetPhysicalAddress()?.GetAddressBytes();
            mac = bytes is { Length: > 0 } ? string.Join(':', bytes.Select(b => b.ToString("X2"))) : null;
        }
        catch
        {
            mac = null;
        }

        return new NetworkAdapterInfo
        {
            Name = nic.Name,
            Description = nic.Description,
            InterfaceType = nic.NetworkInterfaceType.ToString(),
            Status = nic.OperationalStatus.ToString(),
            IsUp = nic.OperationalStatus == OperationalStatus.Up,
            SpeedBps = speed,
            MacAddress = mac,
            IPv4Addresses = ipv4
        };
    }

    public async Task<OperationResult<IReadOnlyList<NetworkConnectionInfo>>> GetActiveConnectionsAsync(CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
            return OperationResult<IReadOnlyList<NetworkConnectionInfo>>.Fail("Network Monitor's connection list requires Windows.", "UNSUPPORTED_OS");

        const string script =
            "try { " +
            "$procMap = @{}; " +
            "Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $procMap[$_.Id] = $_.ProcessName }; " +
            "Get-NetTCPConnection -ErrorAction Stop | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, " +
            "@{N='State';E={$_.State.ToString()}}, OwningProcess, @{N='ProcessName';E={$procMap[$_.OwningProcess]}} | " +
            "ConvertTo-Json -Depth 3 " +
            "} catch { [PSCustomObject]@{ Available = $false; Error = $_.Exception.Message } | ConvertTo-Json }";

        var run = await RunPowerShellAsync(script, QueryTimeout, ct).ConfigureAwait(false);
        if (!run.Success)
            return OperationResult<IReadOnlyList<NetworkConnectionInfo>>.Fail(run.Message, run.ErrorCode);

        try
        {
            return ParseConnectionsJson(run.Value?.Output ?? string.Empty);
        }
        catch (Exception ex)
        {
            return OperationResult<IReadOnlyList<NetworkConnectionInfo>>.Fail(
                $"Could not parse the active connection list: {ex.Message}", "PARSE_ERROR");
        }
    }

    // ---------- Pure JSON parsing (unit-tested) ----------

    internal static OperationResult<IReadOnlyList<NetworkConnectionInfo>> ParseConnectionsJson(string json)
    {
        if (string.IsNullOrWhiteSpace(json))
            return OperationResult<IReadOnlyList<NetworkConnectionInfo>>.Ok(
                Array.Empty<NetworkConnectionInfo>(), "No active TCP connections were reported.");

        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        if (root.ValueKind == JsonValueKind.Object && root.TryGetProperty("Available", out var availableProp))
        {
            // The script's own catch block reported a real failure (e.g. the NetTCPIP
            // module is missing on this Windows edition) — surface it, never an empty
            // "no connections" list that would misrepresent an unknown state as clean.
            var available = availableProp.ValueKind == JsonValueKind.True;
            if (!available)
            {
                var error = root.TryGetProperty("Error", out var errProp) ? errProp.GetString() : null;
                return OperationResult<IReadOnlyList<NetworkConnectionInfo>>.Fail(
                    string.IsNullOrWhiteSpace(error) ? "Could not read active connections." : error!,
                    "NETTCP_UNAVAILABLE");
            }
        }

        IEnumerable<JsonElement> items = root.ValueKind switch
        {
            JsonValueKind.Array => root.EnumerateArray(),
            JsonValueKind.Object => new[] { root },
            _ => Array.Empty<JsonElement>()
        };

        var list = new List<NetworkConnectionInfo>();
        foreach (var item in items)
        {
            var localAddress = GetString(item, "LocalAddress");
            if (localAddress is null)
                continue; // Not a connection record (e.g. this was the failure marker object).

            list.Add(new NetworkConnectionInfo
            {
                LocalAddress = localAddress,
                LocalPort = GetInt(item, "LocalPort"),
                RemoteAddress = GetString(item, "RemoteAddress"),
                RemotePort = GetInt(item, "RemotePort"),
                State = GetString(item, "State") ?? "Unknown",
                OwningProcessId = GetInt(item, "OwningProcess"),
                ProcessName = GetString(item, "ProcessName")
            });
        }

        return OperationResult<IReadOnlyList<NetworkConnectionInfo>>.Ok(
            list, $"{list.Count} active TCP connection(s)/listener(s) read from Get-NetTCPConnection.");
    }

    private static string? GetString(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

    private static int GetInt(JsonElement element, string name)
    {
        if (!element.TryGetProperty(name, out var value))
            return 0;

        if (value.ValueKind == JsonValueKind.Number && value.TryGetInt32(out var n))
            return n;

        return 0;
    }

    // ---------- Process execution (mirrors DefenderService's pattern) ----------

    private static async Task<OperationResult<ProcessRun>> RunPowerShellAsync(string script, TimeSpan timeout, CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows())
            return OperationResult<ProcessRun>.Fail("This check requires Windows (PowerShell NetTCPIP cmdlets).", "UNSUPPORTED_OS");

        return await RunProcessAsync("powershell.exe",
            $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"{script.Replace("\"", "\\\"")}\"",
            timeout, ct).ConfigureAwait(false);
    }

    private static async Task<OperationResult<ProcessRun>> RunProcessAsync(string fileName, string arguments, TimeSpan? timeout, CancellationToken ct)
    {
        try
        {
            var startInfo = new ProcessStartInfo
            {
                FileName = fileName,
                Arguments = arguments,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };

            using var process = new Process { StartInfo = startInfo };
            process.Start();

            using var timeoutCts = timeout.HasValue
                ? new CancellationTokenSource(timeout.Value)
                : new CancellationTokenSource();
            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct, timeoutCts.Token);

            var outputTask = process.StandardOutput.ReadToEndAsync(linkedCts.Token);
            var errorTask = process.StandardError.ReadToEndAsync(linkedCts.Token);

            await process.WaitForExitAsync(linkedCts.Token).ConfigureAwait(false);
            var output = await outputTask.ConfigureAwait(false);
            var error = await errorTask.ConfigureAwait(false);

            return OperationResult<ProcessRun>.Ok(new ProcessRun(process.ExitCode, output, error));
        }
        catch (OperationCanceledException)
        {
            return OperationResult<ProcessRun>.Fail("The operation timed out or was cancelled.", "TIMEOUT");
        }
        catch (Exception ex)
        {
            return OperationResult<ProcessRun>.Fail($"Failed to run '{fileName}': {ex.Message}", "PROCESS_FAILED");
        }
    }

    private sealed record ProcessRun(int ExitCode, string Output, string Error);
}
