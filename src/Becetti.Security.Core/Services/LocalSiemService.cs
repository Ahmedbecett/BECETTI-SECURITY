using System.Diagnostics;
using System.Text.Json;
using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

public interface ILocalSiemService
{
    Task<OperationResult<SiemAuditReport>> CollectAndCorrelateAsync(int maxEventsPerLog = 40, CancellationToken ct = default);
}

/// <summary>
/// #1: Local SIEM &amp; Live Event Correlation Engine.
/// Queries real Windows Event Logs (System, Security, PowerShell Operational, Defender Operational)
/// via Get-WinEvent and applies deterministic correlation rules (Brute-Force 4625, New Service 7045,
/// Log Tampering 1102/104, Defender Detections 1116/1117, Encoded PowerShell 4104). Zero simulation.
/// </summary>
public sealed class LocalSiemService : ILocalSiemService
{
    public async Task<OperationResult<SiemAuditReport>> CollectAndCorrelateAsync(int maxEventsPerLog = 40, CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
            return OperationResult<SiemAuditReport>.Fail("Local SIEM Event Collector requires Windows.", "UNSUPPORTED_OS");

        maxEventsPerLog = Math.Clamp(maxEventsPerLog, 10, 150);

        var script =
            "$logs = @('System','Security','Microsoft-Windows-PowerShell/Operational','Microsoft-Windows-Windows Defender/Operational');" +
            "$out = @();" +
            "foreach ($l in $logs) {" +
            $"  try {{ $evts = Get-WinEvent -LogName $l -MaxEvents {maxEventsPerLog} -ErrorAction Stop;" +
            "    foreach ($e in $evts) {" +
            "      $msg = if ($e.Message) { ($e.Message -replace '\\r?\\n',' ') } else { '' };" +
            "      if ($msg.Length -gt 320) { $msg = $msg.Substring(0,320) };" +
            "      $out += [pscustomobject]@{ LogName=$l; Id=$e.Id; Level=$e.LevelDisplayName; Provider=$e.ProviderName; Time=$e.TimeCreated.ToUniversalTime().ToString('o'); Message=$msg }" +
            "    }" +
            "  } catch { }" +
            "};" +
            "$out | ConvertTo-Json -Compress -Depth 3";

        var json = await RunPowerShellAsync(script, ct).ConfigureAwait(false);
        var events = ParseEventsJson(json);
        var alerts = CorrelateEvents(events);

        var report = new SiemAuditReport
        {
            AuditedAt = DateTimeOffset.UtcNow,
            TotalEventsScanned = events.Count,
            Alerts = alerts,
            RecentEvents = events.OrderByDescending(e => e.Timestamp).Take(120).ToList(),
            Summary = alerts.Count > 0
                ? $"SIEM Alert: {alerts.Count} correlation alert(s) across {events.Count} real Windows events."
                : $"SIEM Clean: {events.Count} real Windows events inspected, 0 high-risk correlation alerts."
        };

        return OperationResult<SiemAuditReport>.Ok(report, report.Summary);
    }

    internal static List<SiemEventEntry> ParseEventsJson(string json)
    {
        var list = new List<SiemEventEntry>();
        if (string.IsNullOrWhiteSpace(json)) return list;

        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            if (root.ValueKind == JsonValueKind.Array)
            {
                foreach (var el in root.EnumerateArray())
                    TryAddEvent(el, list);
            }
            else if (root.ValueKind == JsonValueKind.Object)
            {
                TryAddEvent(root, list);
            }
        }
        catch { }

        return list;
    }

    private static void TryAddEvent(JsonElement el, List<SiemEventEntry> list)
    {
        int id = el.TryGetProperty("Id", out var idEl) && idEl.TryGetInt32(out var v) ? v : 0;
        string log = el.TryGetProperty("LogName", out var lEl) ? lEl.GetString() ?? "" : "";
        string lvl = el.TryGetProperty("Level", out var lvEl) ? lvEl.GetString() ?? "Information" : "Information";
        string prov = el.TryGetProperty("Provider", out var pEl) ? pEl.GetString() ?? "" : "";
        string msg = el.TryGetProperty("Message", out var mEl) ? mEl.GetString() ?? "" : "";
        DateTimeOffset ts = el.TryGetProperty("Time", out var tEl) && DateTimeOffset.TryParse(tEl.GetString(), out var parsed)
            ? parsed
            : DateTimeOffset.UtcNow;

        list.Add(new SiemEventEntry
        {
            EventId = id,
            LogName = log,
            Level = string.IsNullOrWhiteSpace(lvl) ? "Information" : lvl,
            ProviderName = prov,
            Message = msg,
            Timestamp = ts,
            MitreTechniqueId = InferMitreForEvent(id, msg)
        });
    }

    internal static IReadOnlyList<SiemCorrelationAlert> CorrelateEvents(IReadOnlyList<SiemEventEntry> events)
    {
        var alerts = new List<SiemCorrelationAlert>();

        // Rule 1: Failed logon burst (Event ID 4625 >= 5)
        var failedLogons = events.Where(e => e.EventId == 4625).ToList();
        if (failedLogons.Count >= 5)
        {
            alerts.Add(new SiemCorrelationAlert
            {
                RuleId = "SIEM-001",
                Title = "Brute-Force / Repeated Failed Logons Detected",
                Severity = "Critical",
                MitreTechniqueId = "T1110",
                EventCount = failedLogons.Count,
                Evidence = $"{failedLogons.Count} failed Windows logon attempts (Event 4625) in recent log window."
            });
        }

        // Rule 2: Audit / Event log cleared (Event ID 1102 or 104)
        var cleared = events.Where(e => e.EventId is 1102 or 104).ToList();
        if (cleared.Count > 0)
        {
            alerts.Add(new SiemCorrelationAlert
            {
                RuleId = "SIEM-002",
                Title = "Windows Event Log Cleared (Anti-Forensics)",
                Severity = "Critical",
                MitreTechniqueId = "T1070.001",
                EventCount = cleared.Count,
                Evidence = $"Security or System log wipe event ({string.Join(", ", cleared.Select(c => "#" + c.EventId).Distinct())})."
            });
        }

        // Rule 3: Defender malware detection (Event ID 1116 or 1117)
        var defenderHits = events.Where(e => e.EventId is 1116 or 1117).ToList();
        if (defenderHits.Count > 0)
        {
            alerts.Add(new SiemCorrelationAlert
            {
                RuleId = "SIEM-003",
                Title = "Microsoft Defender Real Malware Detection Logged",
                Severity = "Critical",
                MitreTechniqueId = "T1204.002",
                EventCount = defenderHits.Count,
                Evidence = defenderHits[0].Message.Length > 120 ? defenderHits[0].Message[..120] + "…" : defenderHits[0].Message
            });
        }

        // Rule 4: Suspicious PowerShell Script Block (Event ID 4104 with obfuscation/download indicators)
        var suspPs = events.Where(e => e.EventId == 4104 && IsSuspiciousPowerShellMessage(e.Message)).ToList();
        if (suspPs.Count > 0)
        {
            alerts.Add(new SiemCorrelationAlert
            {
                RuleId = "SIEM-004",
                Title = "Suspicious PowerShell Script Block Activity (Event 4104)",
                Severity = "High",
                MitreTechniqueId = "T1059.001",
                EventCount = suspPs.Count,
                Evidence = "Detected download cradle, AMSI bypass, or Base64 execution indicators in PowerShell log."
            });
        }

        // Rule 5: New Windows Service Installed (Event ID 7045)
        var newSvcs = events.Where(e => e.EventId == 7045).ToList();
        if (newSvcs.Count > 0)
        {
            alerts.Add(new SiemCorrelationAlert
            {
                RuleId = "SIEM-005",
                Title = "New Windows Service Installed (Event 7045)",
                Severity = "Medium",
                MitreTechniqueId = "T1543.003",
                EventCount = newSvcs.Count,
                Evidence = newSvcs[0].Message.Length > 120 ? newSvcs[0].Message[..120] + "…" : newSvcs[0].Message
            });
        }

        return alerts;
    }

    private static bool IsSuspiciousPowerShellMessage(string msg)
    {
        var lower = (msg ?? string.Empty).ToLowerInvariant();
        return lower.Contains("frombase64string") ||
               lower.Contains("downloadstring") ||
               lower.Contains("amsiinitfailed") ||
               lower.Contains("invoke-expression") ||
               lower.Contains("-encodedcommand") ||
               lower.Contains("vssadmin delete");
    }

    private static string InferMitreForEvent(int eventId, string msg) => eventId switch
    {
        4625 => "T1110",
        7045 => "T1543.003",
        1102 or 104 => "T1070.001",
        1116 or 1117 => "T1204.002",
        4104 when IsSuspiciousPowerShellMessage(msg) => "T1059.001",
        4698 => "T1053.005",
        _ => string.Empty
    };

    private static async Task<string> RunPowerShellAsync(string command, CancellationToken ct)
    {
        try
        {
            using var p = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"{command.Replace("\"", "\\\"")}\"",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                }
            };
            p.Start();
            var outputTask = p.StandardOutput.ReadToEndAsync(ct);
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(20));
            await p.WaitForExitAsync(cts.Token).ConfigureAwait(false);
            return await outputTask.ConfigureAwait(false);
        }
        catch
        {
            return string.Empty;
        }
    }
}
