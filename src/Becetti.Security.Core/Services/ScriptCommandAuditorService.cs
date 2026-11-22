using System.Diagnostics;
using System.Text;
using System.Text.RegularExpressions;
using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

public interface IScriptCommandAuditorService
{
    Task<OperationResult<ScriptAuditReport>> AuditAsync(CancellationToken ct = default);
    string? TryDecodePowerShellBase64(string commandOrPayload);
    SuspiciousScriptEvent? AnalyzeCommandLine(string source, string processOrHost, string commandLine, DateTimeOffset? timestamp = null);
}

/// <summary>
/// Real Suspicious PowerShell & LOLBins Command Auditor:
/// - Inspects live Windows process command lines via CIM/PowerShell
/// - Reads real Microsoft-Windows-PowerShell/Operational Event ID 4104 (Script Block Logging) via wevtutil
/// - Detects obfuscated PowerShell (-EncodedCommand, IEX, DownloadString, hidden window) & LOLBins (certutil, mshta, rundll32, regsvr32)
/// - Decodes UTF-16LE & UTF-8 Base64 payloads for instant review or BECETTI AI analysis.
/// </summary>
public sealed class ScriptCommandAuditorService : IScriptCommandAuditorService
{
    private static readonly Regex EncodedArgRegex = new(
        @"(?:-e(?:nc(?:odedcommand)?)?\s+|FromBase64String\(\s*['""])([A-Za-z0-9+/=]{16,})",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly (string Pattern, string Label, int Score)[] Indicators =
    {
        (@"-e(?:nc|ncodedcommand)\b", "EncodedCommand", 40),
        (@"FromBase64String", "Base64 Decode", 30),
        (@"DownloadString|DownloadFile|Invoke-WebRequest|\biwr\b|\bcurl\b", "Remote Download", 30),
        (@"Invoke-Expression|\bIEX\b", "Dynamic Execution (IEX)", 30),
        (@"-w(?:indowstyle)?\s+hidden", "Hidden Window", 25),
        (@"-ep\s+bypass|-ExecutionPolicy\s+Bypass", "ExecutionPolicy Bypass", 20),
        (@"certutil\.exe.*(?:-urlcache|-decode)", "Certutil LOLBin Abuse", 45),
        (@"mshta\.exe.*(?:http|javascript|vbscript)", "MSHTA Script Execution", 45),
        (@"rundll32\.exe.*(?:javascript|url\.dll|shell32)", "Rundll32 Proxy Execution", 35),
        (@"regsvr32\.exe.*(?:/i:http|scrobj\.dll)", "Regsvr32 Squiblydoo", 45),
        (@"bitsadmin.*(?:/transfer|/addfile)", "BITSAdmin Transfer", 35),
        (@"Add-MpPreference.*Exclusion|Set-MpPreference.*DisableRealtimeMonitoring", "Defender Tampering", 50)
    };

    public async Task<OperationResult<ScriptAuditReport>> AuditAsync(CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
            return OperationResult<ScriptAuditReport>.Fail("Script & LOLBins Auditor requires Windows.", "UNSUPPORTED_OS");

        var findings = new List<SuspiciousScriptEvent>();
        int procsChecked = 0;
        int blocksChecked = 0;
        var notes = new List<string>();

        // 1. Live process command lines via PowerShell Get-CimInstance Win32_Process
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = "-NoProfile -NonInteractive -Command \"Get-CimInstance Win32_Process | Where-Object { $_.CommandLine } | ForEach-Object { ($_.Name + '|' + $_.ProcessId + '|' + ($_.CommandLine -replace '[\\r\\n]+',' ')) }\"",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };

            using var proc = Process.Start(psi);
            if (proc is not null)
            {
                var stdout = await proc.StandardOutput.ReadToEndAsync(ct).ConfigureAwait(false);
                await proc.WaitForExitAsync(ct).ConfigureAwait(false);

                foreach (var line in stdout.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries))
                {
                    var parts = line.Split('|', 3);
                    if (parts.Length < 3) continue;
                    procsChecked++;

                    var procName = parts[0].Trim();
                    var pid = parts[1].Trim();
                    var cmd = parts[2].Trim();

                    // Skip our own audit command
                    if (cmd.Contains("Get-CimInstance Win32_Process", StringComparison.OrdinalIgnoreCase))
                        continue;

                    var evt = AnalyzeCommandLine("LiveProcess", $"{procName} (PID {pid})", cmd);
                    if (evt is not null)
                        findings.Add(evt);
                }
            }
        }
        catch (Exception ex)
        {
            notes.Add($"Process inspection note: {ex.Message}");
        }

        // 2. PowerShell Script Block Logging (Event ID 4104) via wevtutil
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "wevtutil.exe",
                Arguments = "qe Microsoft-Windows-PowerShell/Operational /q:\"*[System[(EventID=4104)]]\" /c:25 /rd:true /f:text",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };

            using var proc = Process.Start(psi);
            if (proc is not null)
            {
                var stdout = await proc.StandardOutput.ReadToEndAsync(ct).ConfigureAwait(false);
                await proc.WaitForExitAsync(ct).ConfigureAwait(false);

                if (proc.ExitCode == 0 && !string.IsNullOrWhiteSpace(stdout))
                {
                    var blocks = stdout.Split("Event[", StringSplitOptions.RemoveEmptyEntries);
                    blocksChecked = blocks.Length;
                    foreach (var block in blocks)
                    {
                        var evt = AnalyzeCommandLine("PowerShell-4104", "ScriptBlockLog", block.Trim());
                        if (evt is not null)
                            findings.Add(evt);
                    }
                }
                else
                {
                    notes.Add("PowerShell 4104 Event Log unavailable or empty.");
                }
            }
        }
        catch (Exception ex)
        {
            notes.Add($"Event log note: {ex.Message}");
        }

        var report = new ScriptAuditReport
        {
            AuditedAt = DateTimeOffset.UtcNow,
            RunningProcessesChecked = procsChecked,
            EventLogBlocksChecked = blocksChecked,
            Findings = findings.OrderByDescending(f => f.RiskLevel == "Critical").ThenByDescending(f => f.RiskLevel == "High").Take(50).ToList(),
            Note = notes.Count > 0 ? string.Join(" ", notes) : "Live processes and PowerShell 4104 logs audited."
        };

        return OperationResult<ScriptAuditReport>.Ok(
            report,
            report.Findings.Count > 0
                ? $"Detected {report.Findings.Count} suspicious script/LOLBin command(s) across {procsChecked} process(es) and {blocksChecked} event block(s)."
                : $"Clean: 0 suspicious PowerShell/LOLBin patterns across {procsChecked} live process(es) and {blocksChecked} script block(s).");
    }

    public SuspiciousScriptEvent? AnalyzeCommandLine(string source, string processOrHost, string commandLine, DateTimeOffset? timestamp = null)
    {
        if (string.IsNullOrWhiteSpace(commandLine))
            return null;

        int score = 0;
        var matched = new List<string>();

        foreach (var (pattern, label, weight) in Indicators)
        {
            if (Regex.IsMatch(commandLine, pattern, RegexOptions.IgnoreCase))
            {
                score += weight;
                matched.Add(label);
            }
        }

        if (score < 25)
            return null;

        var decoded = TryDecodePowerShellBase64(commandLine);
        var risk = score >= 65 ? "Critical" : score >= 40 ? "High" : "Medium";

        return new SuspiciousScriptEvent
        {
            Timestamp = timestamp ?? DateTimeOffset.UtcNow,
            Source = source,
            ProcessOrHost = processOrHost,
            RawCommand = commandLine.Length > 600 ? commandLine[..600] + "..." : commandLine,
            DecodedBase64 = decoded,
            MatchedIndicators = matched,
            RiskLevel = risk
        };
    }

    public string? TryDecodePowerShellBase64(string commandOrPayload)
    {
        if (string.IsNullOrWhiteSpace(commandOrPayload))
            return null;

        string candidate = commandOrPayload.Trim();
        var m = EncodedArgRegex.Match(candidate);
        if (m.Success)
            candidate = m.Groups[1].Value;

        if (candidate.Length < 12)
            return null;

        // Normalize padding if needed
        int mod = candidate.Length % 4;
        if (mod != 0)
            candidate = candidate.PadRight(candidate.Length + (4 - mod), '=');

        try
        {
            var bytes = Convert.FromBase64String(candidate);
            if (bytes.Length == 0) return null;

            // PowerShell -EncodedCommand uses UTF-16LE (many null high bytes for ASCII text)
            int zeroOddBytes = 0;
            for (int i = 1; i < bytes.Length; i += 2)
            {
                if (bytes[i] == 0) zeroOddBytes++;
            }

            string text = (bytes.Length >= 4 && zeroOddBytes >= bytes.Length / 4)
                ? Encoding.Unicode.GetString(bytes)
                : Encoding.UTF8.GetString(bytes);

            var clean = new string(text.Where(c => !char.IsControl(c) || c is '\r' or '\n' or '\t').ToArray()).Trim();
            return clean.Length >= 4 ? clean : null;
        }
        catch
        {
            return null;
        }
    }
}
