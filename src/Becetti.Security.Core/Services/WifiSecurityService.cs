using System.Diagnostics;
using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

/// <summary>
/// Parses the real, unmodified text output of "netsh wlan show interfaces" —
/// the same command Windows' own Wi-Fi diagnostics are built on. When no
/// wireless adapter is present or nothing is connected, that honest state is
/// returned rather than a guessed network.
/// </summary>
public sealed class WifiSecurityService : IWifiSecurityService
{
    private static readonly TimeSpan QueryTimeout = TimeSpan.FromSeconds(15);

    private static readonly string[] StrongAuthPrefixes = { "WPA2", "WPA3" };

    public async Task<OperationResult<WifiSecurityInfo>> GetCurrentNetworkSecurityAsync(CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
            return OperationResult<WifiSecurityInfo>.Fail("Wi-Fi Security requires Windows.", "UNSUPPORTED_OS");

        var run = await RunProcessAsync("netsh.exe", "wlan show interfaces", QueryTimeout, ct).ConfigureAwait(false);
        if (!run.Success || run.Value is null)
            return OperationResult<WifiSecurityInfo>.Fail(run.Message, run.ErrorCode);

        if (run.Value.ExitCode != 0)
        {
            return OperationResult<WifiSecurityInfo>.Fail(
                string.IsNullOrWhiteSpace(run.Value.Error)
                    ? "netsh could not read the wireless interface (no Wi-Fi adapter, or the WLAN AutoConfig service is stopped)."
                    : run.Value.Error,
                "NETSH_FAILED");
        }

        return OperationResult<WifiSecurityInfo>.Ok(ParseNetshOutput(run.Value.Output), "Wi-Fi state read from netsh wlan show interfaces.");
    }

    internal static WifiSecurityInfo ParseNetshOutput(string output)
    {
        var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var rawLine in output.Split('\n'))
        {
            var line = rawLine.TrimEnd('\r');
            var colonIndex = line.IndexOf(':');
            if (colonIndex <= 0)
                continue;

            var key = line[..colonIndex].Trim();
            var value = line[(colonIndex + 1)..].Trim();
            if (key.Length == 0)
                continue;

            // Only keep the first occurrence of a key (SSID also appears nested under the
            // "Profile" block with the same label on some locales/builds).
            fields.TryAdd(key, value);
        }

        var state = fields.GetValueOrDefault("State");
        var connected = state is not null && state.Contains("connected", StringComparison.OrdinalIgnoreCase)
                        && !state.Contains("disconnected", StringComparison.OrdinalIgnoreCase);

        if (!connected)
            return new WifiSecurityInfo { Connected = false };

        var auth = fields.GetValueOrDefault("Authentication");
        int? signal = null;
        if (fields.TryGetValue("Signal", out var signalRaw) &&
            int.TryParse(signalRaw.TrimEnd('%'), out var signalValue))
        {
            signal = signalValue;
        }

        bool? stronglySecured = null;
        if (!string.IsNullOrWhiteSpace(auth))
            stronglySecured = StrongAuthPrefixes.Any(p => auth.StartsWith(p, StringComparison.OrdinalIgnoreCase));

        return new WifiSecurityInfo
        {
            Connected = true,
            Ssid = fields.GetValueOrDefault("SSID"),
            AuthenticationType = auth,
            CipherType = fields.GetValueOrDefault("Cipher"),
            SignalPercent = signal,
            IsStronglySecured = stronglySecured
        };
    }

    // ---------- Process execution (mirrors DefenderService's pattern) ----------

    private static async Task<OperationResult<ProcessRun>> RunProcessAsync(string fileName, string arguments, TimeSpan timeout, CancellationToken ct)
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

            using var timeoutCts = new CancellationTokenSource(timeout);
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
