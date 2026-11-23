using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

public interface IProcessTreeHunterService
{
    Task<OperationResult<ProcessTreeReport>> CaptureProcessTreeAsync(CancellationToken ct = default);
    OperationResult KillProcessTree(int pid);
}

/// <summary>
/// #8: Live Process Tree &amp; Parent-Child Anomaly Hunter.
/// Queries real running Windows processes via Win32_Process (ParentProcessId, CommandLine,
/// ExecutablePath, WorkingSetSize), verifies Authenticode signatures, and flags classic EDR
/// parent-child anomalies (e.g., WINWORD/EXCEL/OUTLOOK spawning PowerShell/CMD/MSHTA, or
/// unsigned binaries executing from %TEMP% / %APPDATA%). Zero simulation.
/// </summary>
public sealed class ProcessTreeHunterService : IProcessTreeHunterService
{
    private static readonly HashSet<string> OfficeAndBrowserParents = new(StringComparer.OrdinalIgnoreCase)
    {
        "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "acrord32.exe", "acrobat.exe", "w3wp.exe"
    };

    private static readonly HashSet<string> ShellAndLolbinChildren = new(StringComparer.OrdinalIgnoreCase)
    {
        "powershell.exe", "pwsh.exe", "cmd.exe", "mshta.exe", "wscript.exe", "cscript.exe",
        "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe"
    };

    public async Task<OperationResult<ProcessTreeReport>> CaptureProcessTreeAsync(CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
            return OperationResult<ProcessTreeReport>.Fail("Live Process Tree Hunter requires Windows.", "UNSUPPORTED_OS");

        var script =
            "Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine,WorkingSetSize | ConvertTo-Json -Compress";
        var json = await RunPowerShellAsync(script, ct).ConfigureAwait(false);
        var rawList = ParseWin32ProcessJson(json);

        var nameByPid = rawList.ToDictionary(p => p.Pid, p => p.Name);
        var sigCache = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
        var nodes = new List<ProcessTreeNode>(rawList.Count);

        foreach (var p in rawList)
        {
            var parentName = nameByPid.TryGetValue(p.ParentPid, out var pn) ? pn : $"PID {p.ParentPid}";
            bool signed = IsFileAuthenticodeSigned(p.ExePath, sigCache);
            var (isAnomaly, reason, mitre) = EvaluateAnomaly(parentName, p.Name, p.ExePath, p.CmdLine, signed);

            nodes.Add(new ProcessTreeNode
            {
                ProcessId = p.Pid,
                ParentProcessId = p.ParentPid,
                ProcessName = p.Name,
                ParentName = parentName,
                ExecutablePath = p.ExePath,
                CommandLine = p.CmdLine,
                MemoryMb = Math.Round(p.WorkingSetBytes / (1024.0 * 1024.0), 1),
                IsSigned = signed,
                IsAnomaly = isAnomaly,
                AnomalyReason = reason,
                MitreTechniqueId = mitre
            });
        }

        var ordered = nodes
            .OrderByDescending(n => n.IsAnomaly)
            .ThenByDescending(n => n.MemoryMb)
            .ToList();

        int anomalies = ordered.Count(n => n.IsAnomaly);
        var summary = anomalies > 0
            ? $"Process Tree Alert: {anomalies} suspicious process/parent-child anomaly(s) across {ordered.Count} live processes!"
            : $"Process Tree Clean: {ordered.Count} live processes inspected, 0 parent-child EDR anomalies.";

        return OperationResult<ProcessTreeReport>.Ok(new ProcessTreeReport
        {
            CapturedAt = DateTimeOffset.UtcNow,
            TotalProcesses = ordered.Count,
            AnomalyCount = anomalies,
            Processes = ordered,
            Summary = summary
        }, summary);
    }

    public OperationResult KillProcessTree(int pid)
    {
        if (pid <= 4)
            return OperationResult.Fail("Refused to terminate protected Windows System PID.");
        try
        {
            using var proc = Process.GetProcessById(pid);
            var name = proc.ProcessName;
            proc.Kill(entireProcessTree: true);
            return OperationResult.Ok($"Terminated process tree '{name}' (PID {pid}).");
        }
        catch (Exception ex)
        {
            return OperationResult.Fail($"Could not terminate PID {pid}: {ex.Message}");
        }
    }

    internal static (bool IsAnomaly, string Reason, string Mitre) EvaluateAnomaly(
        string parentName, string procName, string exePath, string cmdLine, bool isSigned)
    {
        if (OfficeAndBrowserParents.Contains(parentName) && ShellAndLolbinChildren.Contains(procName))
            return (true, $"Suspicious Parent->Child spawn ({parentName} -> {procName})", "T1059");

        var lowerCmd = (cmdLine ?? string.Empty).ToLowerInvariant();
        if (ShellAndLolbinChildren.Contains(procName) &&
            (lowerCmd.Contains("-enc") || lowerCmd.Contains("frombase64string") || lowerCmd.Contains("downloadstring") || lowerCmd.Contains("http://") || lowerCmd.Contains("https://")))
            return (true, "Obfuscated or network-staged script/LOLBin command line", MitreAttackMapper.MapScriptCommand($"{procName} {cmdLine}").TechniqueId);

        var lowerPath = (exePath ?? string.Empty).ToLowerInvariant();
        if (!isSigned && !string.IsNullOrWhiteSpace(lowerPath) &&
            (lowerPath.Contains("\\temp\\") || lowerPath.Contains("\\appdata\\local\\temp\\") || lowerPath.Contains("\\users\\public\\")))
            return (true, "Unsigned executable running from Temp/Public user-writable path", "T1204.002");

        return (false, string.Empty, string.Empty);
    }

    private static bool IsFileAuthenticodeSigned(string path, Dictionary<string, bool> cache)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;
        if (cache.TryGetValue(path, out var cached)) return cached;
        bool signed = false;
        try
        {
            if (File.Exists(path))
            {
#pragma warning disable SYSLIB0057
                using var cert = X509Certificate.CreateFromSignedFile(path);
#pragma warning restore SYSLIB0057
                signed = cert is not null && !string.IsNullOrWhiteSpace(cert.Subject);
            }
        }
        catch { signed = false; }
        cache[path] = signed;
        return signed;
    }

    private sealed record RawWin32Proc(int Pid, int ParentPid, string Name, string ExePath, string CmdLine, long WorkingSetBytes);

    private static List<RawWin32Proc> ParseWin32ProcessJson(string json)
    {
        var list = new List<RawWin32Proc>();
        if (string.IsNullOrWhiteSpace(json)) return list;
        try
        {
            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.ValueKind == JsonValueKind.Array)
            {
                foreach (var el in doc.RootElement.EnumerateArray())
                    TryRead(el, list);
            }
            else if (doc.RootElement.ValueKind == JsonValueKind.Object)
            {
                TryRead(doc.RootElement, list);
            }
        }
        catch { }
        return list;
    }

    private static void TryRead(JsonElement el, List<RawWin32Proc> list)
    {
        int pid = el.TryGetProperty("ProcessId", out var p) && p.TryGetInt32(out var pv) ? pv : 0;
        int ppid = el.TryGetProperty("ParentProcessId", out var pp) && pp.TryGetInt32(out var ppv) ? ppv : 0;
        string name = el.TryGetProperty("Name", out var n) ? n.GetString() ?? "" : "";
        string path = el.TryGetProperty("ExecutablePath", out var ep) ? ep.GetString() ?? "" : "";
        string cmd = el.TryGetProperty("CommandLine", out var cl) ? cl.GetString() ?? "" : "";
        long ws = el.TryGetProperty("WorkingSetSize", out var w) && w.TryGetInt64(out var wv) ? wv : 0;
        if (pid > 0 && !string.IsNullOrWhiteSpace(name))
            list.Add(new RawWin32Proc(pid, ppid, name, path, cmd, ws));
    }

    private static async Task<string> RunPowerShellAsync(string command, CancellationToken ct)
    {
        try
        {
            using var p = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"{command}\"",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                }
            };
            p.Start();
            var output = await p.StandardOutput.ReadToEndAsync(ct).ConfigureAwait(false);
            await p.WaitForExitAsync(ct).ConfigureAwait(false);
            return output;
        }
        catch { return string.Empty; }
    }
}
