using System.Diagnostics;
using System.Globalization;
using System.Security.Principal;
using System.Text.Json;
using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

/// <summary>
/// Microsoft Defender integration through supported Windows interfaces only:
/// PowerShell Defender cmdlets (Get-MpComputerStatus, Get-MpThreatDetection,
/// Get-NetFirewallProfile, Update-MpSignature, Set-MpPreference, Remove-MpThreat)
/// and the MpCmdRun.exe command-line scanner. No independent verdicts are made:
/// scan results come from MpCmdRun exit codes and Defender's own detection store.
/// </summary>
public sealed class DefenderService : IDefenderService
{
    private static readonly TimeSpan QueryTimeout = TimeSpan.FromSeconds(60);

    public string? FindMpCmdRun()
    {
        if (!OperatingSystem.IsWindows())
            return null;

        var candidates = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Windows Defender", "MpCmdRun.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Windows Defender", "MpCmdRun.exe")
        };

        foreach (var candidate in candidates)
        {
            if (File.Exists(candidate))
                return candidate;
        }

        return null;
    }

    public bool IsElevated()
    {
        if (!OperatingSystem.IsWindows())
            return false;

        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }

    public OperationResult RestartElevated()
    {
        if (!OperatingSystem.IsWindows())
            return OperationResult.Fail("Elevation is only available on Windows.", "UNSUPPORTED_OS");

        try
        {
            var exe = Environment.ProcessPath;
            if (string.IsNullOrWhiteSpace(exe))
                return OperationResult.Fail("Could not determine the current executable path.", "ELEVATION_FAILED");

            var startInfo = new ProcessStartInfo
            {
                FileName = exe,
                UseShellExecute = true,
                Verb = "runas"
            };

            using var process = Process.Start(startInfo);
            return OperationResult.Ok("Restart requested. Approve the UAC prompt to continue elevated.");
        }
        catch (Exception ex)
        {
            return OperationResult.Fail($"Elevation failed: {ex.Message}", "ELEVATION_FAILED");
        }
    }

    public async Task<OperationResult<DefenderStatus>> GetStatusAsync(CancellationToken ct = default)
    {
        const string script = "Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,BehaviorMonitorEnabled,IoavProtectionEnabled,NISEnabled,IsTamperProtected,AntivirusSignatureVersion,AntivirusSignatureLastUpdated,QuickScanEndTime,FullScanEndTime | ConvertTo-Json -Depth 3";
        var run = await RunPowerShellAsync(script, QueryTimeout, ct).ConfigureAwait(false);
        if (!run.Success)
            return OperationResult<DefenderStatus>.Fail(run.Message, run.ErrorCode);

        try
        {
            var status = ParseStatusJson(run.Value ?? string.Empty);
            return OperationResult<DefenderStatus>.Ok(status, "Defender status read from Get-MpComputerStatus.");
        }
        catch (Exception ex)
        {
            return OperationResult<DefenderStatus>.Fail($"Could not parse Defender status: {ex.Message}", "PARSE_ERROR");
        }
    }

    public async Task<OperationResult<IReadOnlyList<FirewallProfileStatus>>> GetFirewallAsync(CancellationToken ct = default)
    {
        const string script = "Get-NetFirewallProfile | Select-Object Name,Enabled | ConvertTo-Json";
        var run = await RunPowerShellAsync(script, QueryTimeout, ct).ConfigureAwait(false);
        if (!run.Success)
            return OperationResult<IReadOnlyList<FirewallProfileStatus>>.Fail(run.Message, run.ErrorCode);

        try
        {
            var list = ParseFirewallJson(run.Value ?? string.Empty);
            return OperationResult<IReadOnlyList<FirewallProfileStatus>>.Ok(list, $"Read {list.Count} firewall profile(s).");
        }
        catch (Exception ex)
        {
            return OperationResult<IReadOnlyList<FirewallProfileStatus>>.Fail($"Could not parse firewall status: {ex.Message}", "PARSE_ERROR");
        }
    }

    public async Task<OperationResult<IReadOnlyList<ThreatInfo>>> GetThreatsAsync(CancellationToken ct = default)
    {
        const string script = "Get-MpThreatDetection | Select-Object ThreatID,ThreatName,SeverityID,CategoryID,Resources,InitialDetectionTime,ActionSuccess,Action | ConvertTo-Json -Depth 4";
        var run = await RunPowerShellAsync(script, QueryTimeout, ct).ConfigureAwait(false);
        if (!run.Success)
            return OperationResult<IReadOnlyList<ThreatInfo>>.Fail(run.Message, run.ErrorCode);

        try
        {
            var threats = ParseThreatsJson(run.Value ?? string.Empty);
            return OperationResult<IReadOnlyList<ThreatInfo>>.Ok(threats, $"Defender reported {threats.Count} detection(s).");
        }
        catch (Exception ex)
        {
            return OperationResult<IReadOnlyList<ThreatInfo>>.Fail($"Could not parse threat detections: {ex.Message}", "PARSE_ERROR");
        }
    }

    public async Task<OperationResult<ScanOutcome>> RunScanAsync(DefenderScanType scanType, string? targetPath = null, CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
            return OperationResult<ScanOutcome>.Fail("Scanning is only available on Windows.", "UNSUPPORTED_OS");

        var mpCmdRun = FindMpCmdRun();
        if (mpCmdRun is null)
            return OperationResult<ScanOutcome>.Fail("Microsoft Defender (MpCmdRun.exe) was not found on this device. BECETTI SECURITY does not install its own engine.", "DEFENDER_MISSING");

        if (scanType == DefenderScanType.Custom)
        {
            if (string.IsNullOrWhiteSpace(targetPath) || (!File.Exists(targetPath) && !Directory.Exists(targetPath)))
                return OperationResult<ScanOutcome>.Fail("Custom scan requires an existing file or folder path.", "INVALID_TARGET");
        }

        var args = scanType switch
        {
            DefenderScanType.Quick => "-Scan -ScanType 1",
            DefenderScanType.Full => "-Scan -ScanType 2",
            DefenderScanType.Custom => $"-Scan -ScanType 3 -File \"{targetPath}\"",
            _ => "-Scan -ScanType 1"
        };

        var startedAt = DateTimeOffset.Now;
        var run = await RunProcessAsync(mpCmdRun, args, timeout: null, ct).ConfigureAwait(false);
        var endedAt = DateTimeOffset.Now;

        if (!run.Success)
        {
            return OperationResult<ScanOutcome>.Fail(run.Message, run.ErrorCode);
        }

        // MpCmdRun exit codes (documented): 0 = completed, no threat found;
        // 2 = threat found; 1 = invalid arguments / error; others = error.
        var exitCode = run.Value!.ExitCode;
        var outcome = new ScanOutcome
        {
            ScanType = scanType,
            TargetPath = targetPath,
            StartedAt = startedAt,
            EndedAt = endedAt,
            ProcessExitCode = exitCode,
            CompletedWithoutThreat = exitCode == 0,
            ThreatFound = exitCode == 2,
            Output = run.Value.Output,
            Error = exitCode is 0 or 2 ? null : $"MpCmdRun exited with code {exitCode}. {run.Value.Error}".Trim()
        };

        var message = outcome.ThreatFound
            ? "Scan completed: Microsoft Defender reported a threat. See Threat Management for details."
            : outcome.CompletedWithoutThreat
                ? "Scan completed: Microsoft Defender found no threats."
                : $"Scan failed with exit code {exitCode}. See output for details.";

        return OperationResult<ScanOutcome>.Ok(outcome, message);
    }

    public async Task<OperationResult> UpdateSignaturesAsync(CancellationToken ct = default)
    {
        var run = await RunPowerShellAsync("Update-MpSignature", QueryTimeout, ct).ConfigureAwait(false);
        if (!run.Success)
            return OperationResult.Fail(run.Message, run.ErrorCode);

        return OperationResult.Ok("Defender signature update completed.");
    }

    public async Task<OperationResult> SetRealTimeProtectionAsync(bool enable, CancellationToken ct = default)
    {
        var disableValue = enable ? "$false" : "$true";
        var script = $"Set-MpPreference -DisableRealtimeMonitoring {disableValue}";
        var run = await RunPowerShellAsync(script, QueryTimeout, ct).ConfigureAwait(false);
        if (!run.Success)
            return OperationResult.Fail(run.Message, run.ErrorCode);

        // Verify by re-reading the actual state instead of trusting the command.
        var verify = await GetStatusAsync(ct).ConfigureAwait(false);
        if (!verify.Success || verify.Value is null)
            return OperationResult.Fail("Preference changed but verification failed: " + (verify.Message ?? "unknown"), "VERIFY_FAILED");

        if (verify.Value.RealTimeProtectionEnabled != enable)
            return OperationResult.Fail($"Real-time protection is still {(verify.Value.RealTimeProtectionEnabled ? "enabled" : "disabled")} after the change request. Tamper protection or policy may be blocking it.", "VERIFY_FAILED");

        return OperationResult.Ok($"Real-time protection is now {(enable ? "enabled" : "disabled")} (verified).");
    }

    public async Task<OperationResult> RemoveThreatAsync(string threatId, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(threatId))
            return OperationResult.Fail("Threat ID is required.", "INVALID_TARGET");

        if (!IsElevated())
            return OperationResult.Fail("Removing threats requires an administrator. Use 'Restart as administrator' and try again.", "ELEVATION_REQUIRED");

        var safeId = threatId.Replace("'", "");
        var run = await RunPowerShellAsync($"Remove-MpThreat -ThreatID '{safeId}'", QueryTimeout, ct).ConfigureAwait(false);
        if (!run.Success)
            return OperationResult.Fail(run.Message, run.ErrorCode);

        var verify = await GetThreatsAsync(ct).ConfigureAwait(false);
        if (verify.Success && verify.Value is not null &&
            verify.Value.Any(t => string.Equals(t.ThreatId, threatId, StringComparison.OrdinalIgnoreCase) && !t.ActionSucceeded))
        {
            return OperationResult.Fail("Defender did not confirm removal of this threat.", "VERIFY_FAILED");
        }

        return OperationResult.Ok("Defender accepted the removal request and confirmed the threat state.");
    }

    // ---------- Process helpers ----------

    private sealed record ProcessRun(int ExitCode, string Output, string Error);

    private static async Task<OperationResult<ProcessRun>> RunPowerShellAsync(string script, TimeSpan timeout, CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows())
            return OperationResult<ProcessRun>.Fail("This check requires Windows (PowerShell Defender cmdlets).", "UNSUPPORTED_OS");

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

    // ---------- Pure JSON parsers (unit-tested) ----------

    internal static DefenderStatus ParseStatusJson(string json)
    {
        if (string.IsNullOrWhiteSpace(json))
            return new DefenderStatus { Available = false, RawError = "Empty response from Get-MpComputerStatus." };

        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        if (root.ValueKind != JsonValueKind.Object)
            return new DefenderStatus { Available = false, RawError = "Unexpected response shape from Get-MpComputerStatus." };

        return new DefenderStatus
        {
            Available = true,
            AntivirusEnabled = GetBool(root, "AntivirusEnabled"),
            RealTimeProtectionEnabled = GetBool(root, "RealTimeProtectionEnabled"),
            BehaviorMonitorEnabled = GetBool(root, "BehaviorMonitorEnabled"),
            IoavProtectionEnabled = GetBool(root, "IoavProtectionEnabled"),
            NetworkProtectionEnabled = GetBool(root, "NISEnabled"),
            TamperProtectionEnabled = GetBool(root, "IsTamperProtected"),
            AntivirusSignatureVersion = GetString(root, "AntivirusSignatureVersion"),
            AntivirusSignatureLastUpdated = GetDate(root, "AntivirusSignatureLastUpdated"),
            QuickScanEndTime = GetDate(root, "QuickScanEndTime"),
            FullScanEndTime = GetDate(root, "FullScanEndTime")
        };
    }

    internal static IReadOnlyList<FirewallProfileStatus> ParseFirewallJson(string json)
    {
        var result = new List<FirewallProfileStatus>();
        if (string.IsNullOrWhiteSpace(json))
            return result;

        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        IEnumerable<JsonElement> items = root.ValueKind switch
        {
            JsonValueKind.Array => root.EnumerateArray(),
            JsonValueKind.Object => new[] { root },
            _ => Array.Empty<JsonElement>()
        };

        foreach (var item in items)
        {
            result.Add(new FirewallProfileStatus
            {
                Name = GetString(item, "Name") ?? "Unknown",
                Enabled = GetBool(item, "Enabled")
            });
        }

        return result;
    }

    internal static IReadOnlyList<ThreatInfo> ParseThreatsJson(string json)
    {
        var result = new List<ThreatInfo>();
        if (string.IsNullOrWhiteSpace(json))
            return result;

        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        IEnumerable<JsonElement> items = root.ValueKind switch
        {
            JsonValueKind.Array => root.EnumerateArray(),
            JsonValueKind.Object => new[] { root },
            _ => Array.Empty<JsonElement>()
        };

        foreach (var item in items)
        {
            var severityId = GetInt(item, "SeverityID");
            var categoryId = GetInt(item, "CategoryID");
            result.Add(new ThreatInfo
            {
                ThreatId = GetString(item, "ThreatID") ?? string.Empty,
                ThreatName = GetString(item, "ThreatName") ?? "Unknown threat",
                Severity = SeverityLabel(severityId),
                Category = CategoryLabel(categoryId),
                Resources = GetString(item, "Resources") ?? string.Empty,
                DetectedAt = GetDate(item, "InitialDetectionTime"),
                ActionSucceeded = GetBool(item, "ActionSuccess"),
                ActionTaken = GetString(item, "Action")
            });
        }

        return result;
    }

    internal static string SeverityLabel(int severityId) => severityId switch
    {
        1 => "Low",
        2 => "Medium",
        3 => "High",
        4 => "Severe",
        5 => "Critical",
        _ => "Unknown"
    };

    internal static string CategoryLabel(int categoryId) => categoryId switch
    {
        1 => "Virus",
        2 => "Worm",
        3 => "Trojan",
        4 => "Backdoor",
        5 => "Spyware",
        6 => "Adware",
        7 => "Rootkit",
        8 => "Exploit",
        9 => "PUP",
        10 => "Ransomware",
        _ => "Other/Unknown"
    };

    private static bool GetBool(JsonElement element, string name)
    {
        if (!element.TryGetProperty(name, out var value))
            return false;

        return value.ValueKind switch
        {
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            JsonValueKind.Number => value.TryGetInt32(out var n) && n != 0,
            JsonValueKind.String => bool.TryParse(value.GetString(), out var b) && b,
            _ => false
        };
    }

    private static int GetInt(JsonElement element, string name)
    {
        if (!element.TryGetProperty(name, out var value))
            return 0;

        if (value.ValueKind == JsonValueKind.Number && value.TryGetInt32(out var n))
            return n;

        if (value.ValueKind == JsonValueKind.String && int.TryParse(value.GetString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed))
            return parsed;

        return 0;
    }

    private static string? GetString(JsonElement element, string name)
    {
        if (!element.TryGetProperty(name, out var value))
            return null;

        return value.ValueKind == JsonValueKind.String ? value.GetString() : null;
    }

    private static DateTimeOffset? GetDate(JsonElement element, string name)
    {
        var text = GetString(element, name);
        if (string.IsNullOrWhiteSpace(text))
            return null;

        return DateTimeOffset.TryParse(text, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var parsed)
            ? parsed
            : null;
    }
}
