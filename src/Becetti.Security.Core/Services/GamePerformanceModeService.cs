using System.Diagnostics;
using System.Text.RegularExpressions;
using Becetti.Security.Core.Models;
using Microsoft.Win32;

namespace Becetti.Security.Core.Services;

/// <summary>
/// Real implementation using powercfg.exe (the same tool Control Panel's
/// Power Options is built on) for the power plan, and the same registry
/// value the Windows Settings app's Game Mode switch writes
/// (HKCU\Software\Microsoft\GameBar\AutoGameModeEnabled). Neither change
/// requires Administrator.
/// </summary>
public sealed class GamePerformanceModeService : IGamePerformanceModeService
{
    // Windows' built-in "High performance" power scheme GUID (SCHEME_MIN) — stable and
    // documented since Windows 7; present on virtually every Windows install even when
    // hidden from the Settings UI on laptops with "balanced"-only presets.
    private const string HighPerformanceGuid = "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c";
    private const string BalancedGuid = "381b4222-f694-41f0-9685-ff5bb260df2e";

    private const string GameBarKeyPath = @"Software\Microsoft\GameBar";
    private const string GameModeValueName = "AutoGameModeEnabled";

    private readonly ISettingsService _settings;

    public GamePerformanceModeService(ISettingsService settings)
    {
        _settings = settings;
    }

    public async Task<OperationResult<GamePerformanceStatus>> GetStatusAsync(CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
            return OperationResult<GamePerformanceStatus>.Fail("Game/Performance Mode requires Windows.", "UNSUPPORTED_OS");

        var (guid, name) = await GetActiveSchemeAsync(ct).ConfigureAwait(false);
        var gameModeEnabled = ReadGameModeValue() == 1;

        var status = new GamePerformanceStatus
        {
            Active = _settings.Current.GamePerformanceModeActive,
            CurrentPowerPlanName = name ?? guid ?? "Unknown",
            WindowsGameModeEnabled = gameModeEnabled
        };

        return OperationResult<GamePerformanceStatus>.Ok(status);
    }

    public async Task<OperationResult> EnableAsync(CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
            return OperationResult.Fail("Game/Performance Mode requires Windows.", "UNSUPPORTED_OS");

        if (_settings.Current.GamePerformanceModeActive)
            return OperationResult.Ok("Game/Performance Mode is already on.");

        try
        {
            var (currentGuid, _) = await GetActiveSchemeAsync(ct).ConfigureAwait(false);
            _settings.Current.GamePerformancePreviousPowerSchemeGuid = currentGuid;
            _settings.Current.GamePerformancePreviousGameModeValue = ReadGameModeValue();

            var setScheme = await RunProcessAsync("powercfg.exe", $"/setactive {HighPerformanceGuid}", TimeSpan.FromSeconds(10), ct).ConfigureAwait(false);
            if (!setScheme.Success || setScheme.Value!.ExitCode != 0)
                return OperationResult.Fail($"Could not switch the power plan: {setScheme.Value?.Error ?? setScheme.Message}", "POWERCFG_FAILED");

            WriteGameModeValue(1);

            _settings.Current.GamePerformanceModeActive = true;
            await _settings.SaveAsync(ct).ConfigureAwait(false);

            return OperationResult.Ok("Game/Performance Mode is on: the power plan is set to High performance and Windows Game Mode is enabled.");
        }
        catch (Exception ex)
        {
            return OperationResult.Fail($"Could not enable Game/Performance Mode: {ex.Message}", "ERROR");
        }
    }

    public async Task<OperationResult> DisableAsync(CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
            return OperationResult.Fail("Game/Performance Mode requires Windows.", "UNSUPPORTED_OS");

        if (!_settings.Current.GamePerformanceModeActive)
            return OperationResult.Ok("Game/Performance Mode is already off.");

        try
        {
            var restoreGuid = _settings.Current.GamePerformancePreviousPowerSchemeGuid ?? BalancedGuid;
            var setScheme = await RunProcessAsync("powercfg.exe", $"/setactive {restoreGuid}", TimeSpan.FromSeconds(10), ct).ConfigureAwait(false);

            if (_settings.Current.GamePerformancePreviousGameModeValue.HasValue)
                WriteGameModeValue(_settings.Current.GamePerformancePreviousGameModeValue.Value);
            else
                ClearGameModeValue();

            _settings.Current.GamePerformanceModeActive = false;
            _settings.Current.GamePerformancePreviousPowerSchemeGuid = null;
            _settings.Current.GamePerformancePreviousGameModeValue = null;
            await _settings.SaveAsync(ct).ConfigureAwait(false);

            return setScheme.Success && setScheme.Value!.ExitCode == 0
                ? OperationResult.Ok("Game/Performance Mode is off: the previous power plan and Game Mode setting were restored.")
                : OperationResult.Ok("Game/Performance Mode turned off, but the previous power plan could not be fully restored — check Power Options.");
        }
        catch (Exception ex)
        {
            return OperationResult.Fail($"Could not disable Game/Performance Mode: {ex.Message}", "ERROR");
        }
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static int? ReadGameModeValue()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(GameBarKeyPath, writable: false);
            var value = key?.GetValue(GameModeValueName);
            return value is int i ? i : null;
        }
        catch
        {
            return null;
        }
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static void WriteGameModeValue(int value)
    {
        try
        {
            using var key = Registry.CurrentUser.CreateSubKey(GameBarKeyPath, writable: true);
            key?.SetValue(GameModeValueName, value, RegistryValueKind.DWord);
        }
        catch
        {
            // Best-effort: Game Mode's own registry value is a convenience toggle, not the
            // primary action (the power plan switch above is) — a failure here is not fatal.
        }
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static void ClearGameModeValue()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(GameBarKeyPath, writable: true);
            key?.DeleteValue(GameModeValueName, throwOnMissingValue: false);
        }
        catch
        {
            // Best-effort, see WriteGameModeValue.
        }
    }

    private static async Task<(string? Guid, string? Name)> GetActiveSchemeAsync(CancellationToken ct)
    {
        var result = await RunProcessAsync("powercfg.exe", "/getactivescheme", TimeSpan.FromSeconds(10), ct).ConfigureAwait(false);
        if (!result.Success || result.Value is null)
            return (null, null);

        return ParseActiveSchemeOutput(result.Value.Output);
    }

    /// <summary>
    /// Parses powercfg.exe's "/getactivescheme" output, e.g.
    /// "Power Scheme GUID: 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c  (High performance)".
    /// Pure string parsing, exercised directly by unit tests — no process is started here.
    /// </summary>
    internal static (string? Guid, string? Name) ParseActiveSchemeOutput(string output)
    {
        var match = Regex.Match(output, @"GUID:\s*([0-9a-fA-F\-]{36})\s*\(([^)]+)\)");
        return match.Success ? (match.Groups[1].Value, match.Groups[2].Value) : (null, null);
    }

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
            return OperationResult<ProcessRun>.Fail("The command timed out.", "TIMEOUT");
        }
        catch (Exception ex)
        {
            return OperationResult<ProcessRun>.Fail($"Could not run {fileName}: {ex.Message}", "PROCESS_ERROR");
        }
    }

    private sealed record ProcessRun(int ExitCode, string Output, string Error);
}
