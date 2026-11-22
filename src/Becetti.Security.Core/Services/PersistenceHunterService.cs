using System.Diagnostics;
using System.Runtime.Versioning;
using System.Text.RegularExpressions;
using Becetti.Security.Core.Models;
using Microsoft.Win32;

namespace Becetti.Security.Core.Services;

public interface IPersistenceHunterService
{
    Task<OperationResult<PersistenceAuditReport>> AuditAsync(CancellationToken ct = default);
    Task<OperationResult> DisableScheduledTaskAsync(string taskName, CancellationToken ct = default);
}

/// <summary>
/// Deep Persistence Hunter (Autoruns Pro): inspects Scheduled Tasks, Windows Services,
/// Winlogon Shell/Userinit, Image File Execution Options (IFEO) debuggers, and AppInit_DLLs,
/// verifying Authenticode signatures via IFileForensicsService. Zero simulation.
/// </summary>
public sealed class PersistenceHunterService : IPersistenceHunterService
{
    private readonly IFileForensicsService _forensics;

    private static readonly string[] SuspiciousPathFragments =
    {
        "\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\", "\\users\\public\\", "\\downloads\\", "\\programdata\\"
    };

    private static readonly string[] HighRiskBinaries =
    {
        "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe",
        "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "cmd.exe"
    };

    public PersistenceHunterService(IFileForensicsService forensics)
    {
        _forensics = forensics;
    }

    public async Task<OperationResult<PersistenceAuditReport>> AuditAsync(CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
            return OperationResult<PersistenceAuditReport>.Fail("Deep Persistence Hunter requires Windows.", "UNSUPPORTED_OS");

        var entries = new List<PersistenceEntry>();

        await Task.Run(() =>
        {
            InspectWinlogon(entries);
            InspectAppInitDlls(entries);
            InspectIfeoDebuggers(entries, ct);
            InspectNonSystemServices(entries, ct);
        }, ct).ConfigureAwait(false);

        await InspectScheduledTasksAsync(entries, ct).ConfigureAwait(false);

        var ordered = entries
            .OrderByDescending(e => RiskWeight(e.RiskLevel))
            .ThenBy(e => e.Category, StringComparer.OrdinalIgnoreCase)
            .ThenBy(e => e.Name, StringComparer.OrdinalIgnoreCase)
            .Take(250)
            .ToList();

        var report = new PersistenceAuditReport
        {
            AuditedAt = DateTimeOffset.UtcNow,
            TotalInspected = entries.Count,
            HighRiskCount = ordered.Count(e => e.RiskLevel is "High" or "Critical"),
            UnsignedCount = ordered.Count(e => e.SignatureStatus is "Unsigned" or "Invalid"),
            Entries = ordered
        };

        return OperationResult<PersistenceAuditReport>.Ok(
            report,
            $"Audited {report.TotalInspected} persistence entry(ies): {report.HighRiskCount} high-risk, {report.UnsignedCount} unsigned/invalid.");
    }

    public async Task<OperationResult> DisableScheduledTaskAsync(string taskName, CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
            return OperationResult.Fail("Requires Windows.", "UNSUPPORTED_OS");

        if (string.IsNullOrWhiteSpace(taskName))
            return OperationResult.Fail("Task name is required.", "INVALID_INPUT");

        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "schtasks.exe",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };
            psi.ArgumentList.Add("/Change");
            psi.ArgumentList.Add("/TN");
            psi.ArgumentList.Add(taskName);
            psi.ArgumentList.Add("/DISABLE");

            using var proc = Process.Start(psi);
            if (proc is null)
                return OperationResult.Fail("Could not start schtasks.exe.", "EXEC_ERROR");

            var stdout = await proc.StandardOutput.ReadToEndAsync(ct).ConfigureAwait(false);
            var stderr = await proc.StandardError.ReadToEndAsync(ct).ConfigureAwait(false);
            await proc.WaitForExitAsync(ct).ConfigureAwait(false);

            return proc.ExitCode == 0
                ? OperationResult.Ok($"Disabled scheduled task '{taskName}'.")
                : OperationResult.Fail($"Could not disable task '{taskName}' (may require Administrator): {(string.IsNullOrWhiteSpace(stderr) ? stdout : stderr).Trim()}", "SCHTASKS_FAILED");
        }
        catch (Exception ex)
        {
            return OperationResult.Fail($"Failed to disable scheduled task: {ex.Message}", "SCHTASKS_ERROR");
        }
    }

    [SupportedOSPlatform("windows")]
    private void InspectWinlogon(List<PersistenceEntry> entries)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon");
            if (key is null) return;

            var shell = key.GetValue("Shell") as string ?? string.Empty;
            var shellNormal = shell.Trim().Equals("explorer.exe", StringComparison.OrdinalIgnoreCase);
            entries.Add(BuildEntry(
                "Winlogon",
                "Winlogon Shell",
                @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell",
                shell,
                shellNormal ? "Low" : "Critical",
                shellNormal ? "Standard Windows Explorer shell." : "Non-standard Winlogon Shell value detected (possible persistence hijack).",
                canDisable: false));

            var userinit = key.GetValue("Userinit") as string ?? string.Empty;
            var userinitParts = userinit.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            var userinitNormal = userinitParts.Length == 1 &&
                                 userinitParts[0].EndsWith(@"\userinit.exe", StringComparison.OrdinalIgnoreCase);
            entries.Add(BuildEntry(
                "Winlogon",
                "Winlogon Userinit",
                @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit",
                userinit,
                userinitNormal ? "Low" : "High",
                userinitNormal ? "Standard Windows Userinit." : "Additional or non-standard executable chained into Userinit.",
                canDisable: false));
        }
        catch { }
    }

    [SupportedOSPlatform("windows")]
    private void InspectAppInitDlls(List<PersistenceEntry> entries)
    {
        try
        {
            foreach (var sub in new[]
            {
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
                @"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows"
            })
            {
                using var key = Registry.LocalMachine.OpenSubKey(sub);
                if (key is null) continue;
                var dlls = (key.GetValue("AppInit_DLLs") as string)?.Trim();
                var load = Convert.ToInt32(key.GetValue("LoadAppInit_DLLs") ?? 0);
                if (!string.IsNullOrWhiteSpace(dlls))
                {
                    entries.Add(BuildEntry(
                        "AppInitDll",
                        "AppInit_DLLs",
                        $@"HKLM\{sub}",
                        dlls,
                        load != 0 ? "Critical" : "Medium",
                        load != 0
                            ? "Active AppInit_DLLs injection configured (loads DLL into every GUI process)."
                            : "AppInit_DLLs value populated (LoadAppInit_DLLs is currently 0).",
                        canDisable: false));
                }
            }
        }
        catch { }
    }

    [SupportedOSPlatform("windows")]
    private void InspectIfeoDebuggers(List<PersistenceEntry> entries, CancellationToken ct)
    {
        try
        {
            using var root = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options");
            if (root is null) return;

            foreach (var subName in root.GetSubKeyNames())
            {
                if (ct.IsCancellationRequested) break;
                try
                {
                    using var sub = root.OpenSubKey(subName);
                    var debugger = (sub?.GetValue("Debugger") as string)?.Trim();
                    if (string.IsNullOrWhiteSpace(debugger)) continue;

                    var benign = debugger.Contains("vsjitdebugger", StringComparison.OrdinalIgnoreCase) ||
                                 debugger.Contains("procexp", StringComparison.OrdinalIgnoreCase);

                    entries.Add(BuildEntry(
                        "IfeoDebugger",
                        subName,
                        $@"HKLM\...\Image File Execution Options\{subName}",
                        debugger,
                        benign ? "Low" : "Critical",
                        benign
                            ? "Known developer/Sysinternals debugger registration."
                            : $"IFEO Debugger hijack attached to '{subName}'.",
                        canDisable: false));
                }
                catch { }
            }
        }
        catch { }
    }

    [SupportedOSPlatform("windows")]
    private void InspectNonSystemServices(List<PersistenceEntry> entries, CancellationToken ct)
    {
        try
        {
            using var root = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
            if (root is null) return;

            int checkedCount = 0;
            foreach (var svcName in root.GetSubKeyNames())
            {
                if (ct.IsCancellationRequested || checkedCount >= 180) break;
                try
                {
                    using var sub = root.OpenSubKey(svcName);
                    if (sub is null) continue;
                    var start = Convert.ToInt32(sub.GetValue("Start") ?? 4);
                    var type = Convert.ToInt32(sub.GetValue("Type") ?? 0);
                    if (start > 2) continue; // Auto-start or Boot/System only
                    if ((type & 0x30) == 0) continue; // Win32 own/share process services

                    var imagePath = (sub.GetValue("ImagePath") as string)?.Trim();
                    if (string.IsNullOrWhiteSpace(imagePath)) continue;

                    var expanded = Environment.ExpandEnvironmentVariables(imagePath);
                    if (expanded.Contains("svchost.exe", StringComparison.OrdinalIgnoreCase)) continue;
                    if (expanded.StartsWith(Environment.SystemDirectory, StringComparison.OrdinalIgnoreCase)) continue;

                    checkedCount++;
                    entries.Add(BuildEntry(
                        "Service",
                        svcName,
                        $@"HKLM\SYSTEM\CurrentControlSet\Services\{svcName}",
                        expanded,
                        defaultRisk: null,
                        defaultReason: null,
                        canDisable: false));
                }
                catch { }
            }
        }
        catch { }
    }

    private async Task InspectScheduledTasksAsync(List<PersistenceEntry> entries, CancellationToken ct)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "schtasks.exe",
                Arguments = "/Query /FO CSV /V",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };
            using var proc = Process.Start(psi);
            if (proc is null) return;

            var output = await proc.StandardOutput.ReadToEndAsync(ct).ConfigureAwait(false);
            await proc.WaitForExitAsync(ct).ConfigureAwait(false);

            var lines = output.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries);
            if (lines.Length < 2) return;

            var headers = ParseCsvRow(lines[0]);
            int nameIdx = FindColumn(headers, "TaskName");
            int cmdIdx = FindColumn(headers, "Task To Run");
            int statusIdx = FindColumn(headers, "Status");
            if (nameIdx < 0 || cmdIdx < 0) return;

            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            for (int i = 1; i < lines.Length && entries.Count < 400; i++)
            {
                if (ct.IsCancellationRequested) break;
                var cols = ParseCsvRow(lines[i]);
                if (cols.Count <= Math.Max(nameIdx, cmdIdx)) continue;

                var taskName = cols[nameIdx].Trim();
                var cmd = cols[cmdIdx].Trim();
                var status = statusIdx >= 0 && statusIdx < cols.Count ? cols[statusIdx].Trim() : string.Empty;

                if (string.IsNullOrWhiteSpace(taskName) || taskName.Equals("TaskName", StringComparison.OrdinalIgnoreCase))
                    continue;
                if (taskName.StartsWith("\\Microsoft\\Windows\\", StringComparison.OrdinalIgnoreCase))
                    continue;
                if (string.IsNullOrWhiteSpace(cmd) || cmd.Equals("COM handler", StringComparison.OrdinalIgnoreCase))
                    continue;
                if (status.Equals("Disabled", StringComparison.OrdinalIgnoreCase))
                    continue;
                if (!seen.Add(taskName))
                    continue;

                entries.Add(BuildEntry(
                    "ScheduledTask",
                    taskName,
                    "Windows Task Scheduler",
                    cmd,
                    defaultRisk: null,
                    defaultReason: null,
                    canDisable: true));
            }
        }
        catch { }
    }

    private PersistenceEntry BuildEntry(
        string category,
        string name,
        string location,
        string command,
        string? defaultRisk,
        string? defaultReason,
        bool canDisable)
    {
        var exePath = ExtractExecutablePath(command);
        string sigStatus = "NotChecked";
        string? publisher = null;

        if (!string.IsNullOrWhiteSpace(exePath))
        {
            if (File.Exists(exePath))
            {
                var auth = _forensics.VerifyAuthenticode(exePath);
                if (auth.IsTrusted && auth.IsSigned)
                {
                    sigStatus = "Signed";
                    publisher = auth.Subject;
                }
                else if (auth.IsSigned)
                {
                    sigStatus = "Invalid";
                    publisher = auth.Subject;
                }
                else
                {
                    sigStatus = "Unsigned";
                }
            }
            else
            {
                sigStatus = "Missing";
            }
        }

        string risk = defaultRisk ?? "Low";
        string reason = defaultReason ?? "Verified binary.";

        if (defaultRisk is null)
        {
            var lowerCmd = command.ToLowerInvariant();
            var inSuspiciousFolder = SuspiciousPathFragments.Any(f => lowerCmd.Contains(f));
            var usesLolBin = HighRiskBinaries.Any(b => lowerCmd.Contains(b));
            var encodedOrDownload = lowerCmd.Contains("-enc") || lowerCmd.Contains("downloadstring") ||
                                    lowerCmd.Contains("frombase64string") || lowerCmd.Contains("http://") ||
                                    lowerCmd.Contains("https://");

            if (encodedOrDownload && usesLolBin)
            {
                risk = "Critical";
                reason = "Uses script/LOLBin interpreter with encoded or remote download arguments.";
            }
            else if (inSuspiciousFolder && sigStatus is "Unsigned" or "Invalid")
            {
                risk = "High";
                reason = "Unsigned executable located in user-writable temporary/AppData/Public folder.";
            }
            else if (sigStatus is "Invalid")
            {
                risk = "High";
                reason = "Executable has an untrusted or tampered Authenticode signature.";
            }
            else if (sigStatus is "Unsigned")
            {
                risk = "Medium";
                reason = "Executable is not digitally signed (Authenticode).";
            }
            else if (usesLolBin)
            {
                risk = "Medium";
                reason = "Executes a scripting/system interpreter (review arguments carefully).";
            }
            else
            {
                risk = "Low";
                reason = sigStatus == "Signed" ? "Valid Authenticode signature verified." : "Standard entry.";
            }
        }

        return new PersistenceEntry
        {
            Category = category,
            Name = name,
            SourceLocation = location,
            Command = command,
            ExecutablePath = exePath,
            SignatureStatus = sigStatus,
            Publisher = publisher,
            RiskLevel = risk,
            RiskReason = reason,
            CanDisable = canDisable
        };
    }

    internal static string? ExtractExecutablePath(string command)
    {
        if (string.IsNullOrWhiteSpace(command))
            return null;

        var expanded = Environment.ExpandEnvironmentVariables(command.Trim());
        if (expanded.StartsWith('"'))
        {
            var endQuote = expanded.IndexOf('"', 1);
            if (endQuote > 1)
                return expanded[1..endQuote];
        }

        var match = Regex.Match(expanded, "^([A-Za-z]:\\\\[^\"]+\\.(?:exe|dll|sys|bat|cmd|ps1|vbs))", RegexOptions.IgnoreCase);
        if (match.Success)
            return match.Groups[1].Value;

        var firstToken = expanded.Split(' ', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();
        if (!string.IsNullOrWhiteSpace(firstToken) && Path.IsPathRooted(firstToken))
            return firstToken;

        return null;
    }

    private static int FindColumn(List<string> headers, string expected)
    {
        for (int i = 0; i < headers.Count; i++)
        {
            if (headers[i].Trim().Equals(expected, StringComparison.OrdinalIgnoreCase))
                return i;
        }
        return -1;
    }

    private static List<string> ParseCsvRow(string line)
    {
        var result = new List<string>();
        bool inQuotes = false;
        var current = new System.Text.StringBuilder();
        for (int i = 0; i < line.Length; i++)
        {
            char c = line[i];
            if (c == '"')
            {
                if (inQuotes && i + 1 < line.Length && line[i + 1] == '"')
                {
                    current.Append('"');
                    i++;
                }
                else
                {
                    inQuotes = !inQuotes;
                }
            }
            else if (c == ',' && !inQuotes)
            {
                result.Add(current.ToString());
                current.Clear();
            }
            else
            {
                current.Append(c);
            }
        }
        result.Add(current.ToString());
        return result;
    }

    private static int RiskWeight(string risk) => risk switch
    {
        "Critical" => 4,
        "High" => 3,
        "Medium" => 2,
        _ => 1
    };
}
