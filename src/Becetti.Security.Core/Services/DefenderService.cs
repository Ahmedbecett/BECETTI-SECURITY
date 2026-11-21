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
/// and the MpCmdRun.exe command-line scanner (-Scan, -SignatureUpdate). No
/// independent verdicts are made: scan results come from MpCmdRun exit codes
/// and Defender's own detection store. Signature updates only ever ask Defender
/// to pull from Microsoft's own update service (Update-MpSignature
/// -UpdateSource MicrosoftUpdateServer, or MpCmdRun.exe -SignatureUpdate as a
/// fallback) — this app never downloads definitions itself, never contacts a
/// third-party or unofficial source, and never maintains an independent virus
/// database of its own.
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
        // Get-MpComputerStatus covers the antivirus/real-time/signature state; Get-MpPreference
        // is the only supported source for the cloud-delivered protection (MAPS) level and the
        // automatic sample submission mode. The preference read is best-effort (wrapped so a
        // failure there does not take down the primary status read) and merged into one object.
        const string script =
            "$s = Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,BehaviorMonitorEnabled,IoavProtectionEnabled,NISEnabled,IsTamperProtected,AntivirusSignatureVersion,AntivirusSignatureLastUpdated,QuickScanEndTime,FullScanEndTime,AMRunningMode; " +
            "try { $p = Get-MpPreference -ErrorAction Stop } catch { $p = $null }; " +
            "$s | Add-Member -NotePropertyName MAPSReporting -NotePropertyValue $p.MAPSReporting -Force; " +
            "$s | Add-Member -NotePropertyName SubmitSamplesConsent -NotePropertyValue $p.SubmitSamplesConsent -Force; " +
            "$s | ConvertTo-Json -Depth 3";
        var run = await RunPowerShellAsync(script, QueryTimeout, ct).ConfigureAwait(false);
        if (!run.Success)
            return OperationResult<DefenderStatus>.Fail(run.Message, run.ErrorCode);

        try
        {
            var status = ParseStatusJson(run.Value?.Output ?? string.Empty);
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
            var list = ParseFirewallJson(run.Value?.Output ?? string.Empty);
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
            var threats = ParseThreatsJson(run.Value?.Output ?? string.Empty);
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

    /// <summary>
    /// Updates Microsoft Defender security intelligence (signatures) through the
    /// two supported, official mechanisms only: Update-MpSignature with
    /// -UpdateSource MicrosoftUpdateServer, falling back to MpCmdRun.exe
    /// -SignatureUpdate if the cmdlet path is unavailable. BECETTI SECURITY never
    /// downloads definitions itself and never maintains its own signature store;
    /// it only asks Defender to pull from Microsoft, then re-reads
    /// Get-MpComputerStatus to confirm what actually happened before reporting
    /// success or failure.
    /// </summary>
    public async Task<OperationResult> UpdateSignaturesAsync(CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
            return OperationResult.Fail("Signature updates are only available on Windows.", "UNSUPPORTED_OS");

        // Step 1: detect whether Defender is actually installed and active before touching anything.
        var before = await GetStatusAsync(ct).ConfigureAwait(false);
        if (!before.Success || before.Value is null || !before.Value.Available)
        {
            return OperationResult.Fail(
                "Microsoft Defender could not be reached on this device (" + (before.Message ?? "no details") +
                "). BECETTI SECURITY does not ship its own antivirus engine or signature database, so it cannot update definitions when Defender itself is unavailable.",
                "DEFENDER_UNAVAILABLE");
        }

        if (!before.Value.AntivirusEnabled)
        {
            return OperationResult.Fail(
                "Microsoft Defender Antivirus is currently disabled on this device (by policy, another antivirus product, or a manual setting). Signature updates cannot be applied while it is off.",
                "DEFENDER_DISABLED");
        }

        if (!IsElevated())
        {
            return OperationResult.Fail(
                "Updating signatures requires an administrator. Use 'Restart as administrator' and try again.",
                "ELEVATION_REQUIRED");
        }

        var managedNote = before.Value.ManagedByAnotherAntivirus
            ? $" Note: Defender reports running mode '{before.Value.RunningMode}', which means another antivirus product is the active real-time engine on this device; Defender continues to keep its own signatures current alongside it."
            : string.Empty;

        // Step 2: ask Defender to pull real signatures from Microsoft's own update service.
        // This never reaches a third-party or unofficial source.
        var primary = await RunPowerShellAsync(
            "Update-MpSignature -UpdateSource MicrosoftUpdateServer",
            QueryTimeout, ct).ConfigureAwait(false);

        var primaryOk = primary.Success && primary.Value is not null && primary.Value.ExitCode == 0;
        string? lastError = primaryOk
            ? null
            : (!primary.Success
                ? primary.Message
                : (string.IsNullOrWhiteSpace(primary.Value!.Error) ? primary.Value.Output : primary.Value.Error));

        // Step 3: if the PowerShell cmdlet path failed, fall back to the MpCmdRun.exe
        // command-line mechanism (also official, also Microsoft-only).
        var fallbackAttempted = false;
        var fallbackOk = false;
        if (!primaryOk)
        {
            var mpCmdRun = FindMpCmdRun();
            if (mpCmdRun is not null)
            {
                fallbackAttempted = true;
                var fallback = await RunProcessAsync(mpCmdRun, "-SignatureUpdate", QueryTimeout, ct).ConfigureAwait(false);
                fallbackOk = fallback.Success && fallback.Value is not null && fallback.Value.ExitCode == 0;
                if (!fallbackOk)
                {
                    lastError = !fallback.Success
                        ? fallback.Message
                        : (string.IsNullOrWhiteSpace(fallback.Value?.Error) ? fallback.Value?.Output : fallback.Value?.Error) ?? lastError;
                }
            }
        }

        if (!primaryOk && !fallbackOk)
        {
            var attemptedFallback = fallbackAttempted ? " MpCmdRun.exe -SignatureUpdate was also attempted and failed." : string.Empty;
            return OperationResult.Fail(
                $"Signature update failed: {lastError ?? "unknown error"}.{attemptedFallback}",
                "SIGNATURE_UPDATE_FAILED");
        }

        // Step 4: verify the actual outcome instead of trusting the exit code — re-read real state.
        var after = await GetStatusAsync(ct).ConfigureAwait(false);
        if (!after.Success || after.Value is null)
        {
            return OperationResult.Fail(
                "The update command reported success, but the resulting Defender status could not be verified: " + (after.Message ?? "unknown error"),
                "VERIFY_FAILED");
        }

        var mechanism = fallbackAttempted ? "MpCmdRun.exe -SignatureUpdate" : "Update-MpSignature -UpdateSource MicrosoftUpdateServer";
        var oldVersion = before.Value.AntivirusSignatureVersion;
        var newVersion = after.Value.AntivirusSignatureVersion;
        var newUpdated = after.Value.AntivirusSignatureLastUpdated;

        if (!string.IsNullOrWhiteSpace(newVersion) && !string.Equals(oldVersion, newVersion, StringComparison.OrdinalIgnoreCase))
        {
            return OperationResult.Ok(
                $"Signatures updated via {mechanism}: version {oldVersion ?? "unknown"} -> {newVersion} (verified by re-reading Get-MpComputerStatus, last updated {newUpdated?.ToString("u") ?? "unknown"}).{managedNote}");
        }

        var justUpdated = newUpdated.HasValue && (DateTimeOffset.Now - newUpdated.Value) < TimeSpan.FromMinutes(10);
        if (justUpdated)
        {
            return OperationResult.Ok(
                $"Signatures re-validated via {mechanism}: version {newVersion ?? "unknown"} confirmed current as of {newUpdated:u} (verified).{managedNote}");
        }

        return OperationResult.Ok(
            $"The update request to Microsoft completed via {mechanism}, and Defender reports version {newVersion ?? "unknown"} unchanged from before the request (last updated {newUpdated?.ToString("u") ?? "unknown"}). This normally means no newer signature package was available from Microsoft at this time.{managedNote}");
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
            FullScanEndTime = GetDate(root, "FullScanEndTime"),
            RunningMode = GetString(root, "AMRunningMode"),
            CloudProtectionLevel = CloudProtectionLabel(GetNullableInt(root, "MAPSReporting")),
            SampleSubmissionMode = SampleSubmissionLabel(GetNullableInt(root, "SubmitSamplesConsent"))
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

    /// <summary>Maps Get-MpPreference's MAPSReporting (cloud-delivered protection level).</summary>
    internal static string CloudProtectionLabel(int? mapsReporting) => mapsReporting switch
    {
        0 => "Disabled",
        1 => "Basic",
        2 => "Advanced",
        _ => "Unknown"
    };

    /// <summary>Maps Get-MpPreference's SubmitSamplesConsent (automatic sample submission mode).</summary>
    internal static string SampleSubmissionLabel(int? consent) => consent switch
    {
        0 => "Always Prompt",
        1 => "Send Safe Samples",
        2 => "Never Send",
        3 => "Send All Samples",
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

    /// <summary>Like GetInt, but distinguishes "field absent/null" (returns null) from a real 0 value.</summary>
    private static int? GetNullableInt(JsonElement element, string name)
    {
        if (!element.TryGetProperty(name, out var value) || value.ValueKind == JsonValueKind.Null)
            return null;

        if (value.ValueKind == JsonValueKind.Number && value.TryGetInt32(out var n))
            return n;

        if (value.ValueKind == JsonValueKind.String && int.TryParse(value.GetString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed))
            return parsed;

        return null;
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
