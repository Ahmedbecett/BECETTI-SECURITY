using System.Diagnostics;
using System.Globalization;
using System.Text.Json;
using Becetti.Security.Core.Models;
using Microsoft.Win32;

namespace Becetti.Security.Core.Services;

/// <summary>
/// Platform/identity security: a single combined PowerShell read of TPM
/// (Get-Tpm), Secure Boot (Confirm-SecureBootUEFI), Credential Guard
/// (Win32_DeviceGuard) and BitLocker (Get-BitLockerVolume) — one process
/// spawn instead of four. Each sub-check fails independently and honestly
/// (Available=false with the real error) rather than the whole read failing
/// because one feature is unsupported on this edition/hardware.
/// </summary>
public sealed class PlatformSecurityService : IPlatformSecurityService
{
    private static readonly TimeSpan QueryTimeout = TimeSpan.FromSeconds(45);

    public async Task<OperationResult<PlatformSecuritySnapshot>> GetSnapshotAsync(CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
            return OperationResult<PlatformSecuritySnapshot>.Fail("Platform security checks require Windows.", "UNSUPPORTED_OS");

        const string script =
            "$result = @{}; " +
            "try { $t = Get-Tpm -ErrorAction Stop; $result.Tpm = @{Available=$true; Present=$t.TpmPresent; Ready=$t.TpmReady; ManufacturerVersion=$t.ManufacturerVersion} } catch { $result.Tpm = @{Available=$false; Error=$_.Exception.Message} }; " +
            "try { $sb = Confirm-SecureBootUEFI -ErrorAction Stop; $result.SecureBoot = @{Available=$true; Enabled=$sb} } catch { $result.SecureBoot = @{Available=$false; Error=$_.Exception.Message} }; " +
            "try { $dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\\Microsoft\\Windows\\DeviceGuard -ErrorAction Stop; $running = @($dg.SecurityServicesRunning); $result.CredentialGuard = @{Available=$true; Running=($running -contains 1)} } catch { $result.CredentialGuard = @{Available=$false; Error=$_.Exception.Message} }; " +
            "try { $bl = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop; $result.BitLocker = @{Available=$true; MountPoint=$bl.MountPoint; ProtectionStatus=$bl.ProtectionStatus.ToString()} } catch { $result.BitLocker = @{Available=$false; Error=$_.Exception.Message} }; " +
            "$result | ConvertTo-Json -Depth 5";

        var run = await RunPowerShellAsync(script, QueryTimeout, ct).ConfigureAwait(false);
        if (!run.Success)
            return OperationResult<PlatformSecuritySnapshot>.Fail(run.Message, run.ErrorCode);

        try
        {
            return OperationResult<PlatformSecuritySnapshot>.Ok(
                ParseSnapshotJson(run.Value?.Output ?? string.Empty),
                "Platform security state read from Windows (Get-Tpm / Confirm-SecureBootUEFI / Win32_DeviceGuard / Get-BitLockerVolume).");
        }
        catch (Exception ex)
        {
            return OperationResult<PlatformSecuritySnapshot>.Fail($"Could not parse platform security state: {ex.Message}", "PARSE_ERROR");
        }
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    public Task<OperationResult<WindowsUpdateStatus>> GetWindowsUpdateStatusAsync()
    {
        if (!OperatingSystem.IsWindows())
            return Task.FromResult(OperationResult<WindowsUpdateStatus>.Fail("Windows Update status requires Windows.", "UNSUPPORTED_OS"));

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install");
            var raw = key?.GetValue("LastSuccessTime") as string;

            DateTimeOffset? parsed = null;
            if (!string.IsNullOrWhiteSpace(raw) &&
                (DateTimeOffset.TryParse(raw, CultureInfo.CurrentCulture, DateTimeStyles.AssumeLocal, out var local) ||
                 DateTimeOffset.TryParse(raw, CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal, out local)))
            {
                parsed = local;
            }

            return Task.FromResult(OperationResult<WindowsUpdateStatus>.Ok(
                new WindowsUpdateStatus { Available = true, LastSuccessInstallTime = parsed },
                "Windows Update history read from the registry."));
        }
        catch (Exception ex)
        {
            return Task.FromResult(OperationResult<WindowsUpdateStatus>.Fail($"Could not read Windows Update history: {ex.Message}", "REGISTRY_ERROR"));
        }
    }

    // ---------- Pure JSON parsing (unit-tested) ----------

    internal static PlatformSecuritySnapshot ParseSnapshotJson(string json)
    {
        if (string.IsNullOrWhiteSpace(json))
            return new PlatformSecuritySnapshot();

        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        if (root.ValueKind != JsonValueKind.Object)
            return new PlatformSecuritySnapshot();

        return new PlatformSecuritySnapshot
        {
            Tpm = ParseTpm(root),
            SecureBoot = ParseSecureBoot(root),
            CredentialGuard = ParseCredentialGuard(root),
            DiskEncryption = ParseDiskEncryption(root)
        };
    }

    internal static TpmStatus ParseTpm(JsonElement root)
    {
        if (!root.TryGetProperty("Tpm", out var tpm) || tpm.ValueKind != JsonValueKind.Object)
            return new TpmStatus { Available = false, RawError = "No TPM data returned." };

        if (!GetBool(tpm, "Available"))
            return new TpmStatus { Available = false, RawError = GetString(tpm, "Error") };

        return new TpmStatus
        {
            Available = true,
            Present = GetBool(tpm, "Present"),
            Ready = GetBool(tpm, "Ready"),
            ManufacturerVersion = GetString(tpm, "ManufacturerVersion")
        };
    }

    internal static SecureBootStatus ParseSecureBoot(JsonElement root)
    {
        if (!root.TryGetProperty("SecureBoot", out var sb) || sb.ValueKind != JsonValueKind.Object)
            return new SecureBootStatus { Available = false, RawError = "No Secure Boot data returned." };

        if (!GetBool(sb, "Available"))
            return new SecureBootStatus { Available = false, RawError = GetString(sb, "Error") };

        return new SecureBootStatus { Available = true, Enabled = GetBool(sb, "Enabled") };
    }

    internal static CredentialGuardStatus ParseCredentialGuard(JsonElement root)
    {
        if (!root.TryGetProperty("CredentialGuard", out var dg) || dg.ValueKind != JsonValueKind.Object)
            return new CredentialGuardStatus { Available = false, RawError = "No Credential Guard data returned." };

        if (!GetBool(dg, "Available"))
            return new CredentialGuardStatus { Available = false, RawError = GetString(dg, "Error") };

        return new CredentialGuardStatus { Available = true, Running = GetBool(dg, "Running") };
    }

    internal static DiskEncryptionStatus ParseDiskEncryption(JsonElement root)
    {
        if (!root.TryGetProperty("BitLocker", out var bl) || bl.ValueKind != JsonValueKind.Object)
            return new DiskEncryptionStatus { Available = false, RawError = "No BitLocker data returned." };

        if (!GetBool(bl, "Available"))
            return new DiskEncryptionStatus { Available = false, RawError = GetString(bl, "Error") };

        return new DiskEncryptionStatus
        {
            Available = true,
            MountPoint = GetString(bl, "MountPoint"),
            ProtectionStatus = GetString(bl, "ProtectionStatus")
        };
    }

    private static bool GetBool(JsonElement element, string name)
    {
        if (!element.TryGetProperty(name, out var value))
            return false;

        return value.ValueKind switch
        {
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            _ => false
        };
    }

    private static string? GetString(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

    // ---------- Process execution (mirrors DefenderService's pattern) ----------

    private static async Task<OperationResult<ProcessRun>> RunPowerShellAsync(string script, TimeSpan timeout, CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows())
            return OperationResult<ProcessRun>.Fail("This check requires Windows (PowerShell).", "UNSUPPORTED_OS");

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
