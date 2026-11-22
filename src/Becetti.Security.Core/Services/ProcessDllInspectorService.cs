using System.Diagnostics;
using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

public interface IProcessDllInspectorService
{
    Task<OperationResult<ProcessDllAuditReport>> AuditLoadedModulesAsync(int? targetPid = null, CancellationToken ct = default);
}

/// <summary>
/// Live Process DLL &amp; Module Inspector: enumerates real loaded ProcessModule DLLs
/// inside running Windows processes, verifies Authenticode digital signatures via
/// IFileForensicsService, and flags unsigned DLLs or DLLs injected from user-writable folders.
/// Zero simulation.
/// </summary>
public sealed class ProcessDllInspectorService : IProcessDllInspectorService
{
    private readonly IFileForensicsService _forensics;

    private static readonly string[] SuspiciousDllFolders =
    {
        "\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\", "\\users\\public\\", "\\downloads\\", "\\programdata\\"
    };

    public ProcessDllInspectorService(IFileForensicsService forensics)
    {
        _forensics = forensics;
    }

    public async Task<OperationResult<ProcessDllAuditReport>> AuditLoadedModulesAsync(int? targetPid = null, CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
            return OperationResult<ProcessDllAuditReport>.Fail("Live Process DLL Inspector requires Windows.", "UNSUPPORTED_OS");

        var results = new List<ProcessDllInfo>();
        int processesScanned = 0;
        int totalModulesInspected = 0;

        await Task.Run(() =>
        {
            var sigCache = new Dictionary<string, AuthenticodeInfo>(StringComparer.OrdinalIgnoreCase);
            var winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);

            Process[] processes;
            if (targetPid.HasValue)
            {
                try { processes = new[] { Process.GetProcessById(targetPid.Value) }; }
                catch { processes = Array.Empty<Process>(); }
            }
            else
            {
                processes = Process.GetProcesses()
                    .OrderByDescending(p =>
                    {
                        try { return p.WorkingSet64; } catch { return 0L; }
                    })
                    .Take(40)
                    .ToArray();
            }

            foreach (var proc in processes)
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    ProcessModuleCollection modules;
                    try { modules = proc.Modules; }
                    catch { continue; }

                    processesScanned++;
                    string procName = proc.ProcessName;
                    int pid = proc.Id;

                    foreach (ProcessModule mod in modules)
                    {
                        ct.ThrowIfCancellationRequested();
                        var path = mod.FileName;
                        if (string.IsNullOrWhiteSpace(path))
                            continue;

                        totalModulesInspected++;

                        // Skip trusted Windows System32/WinSxS binaries unless auditing a single specific PID
                        bool isSystemCore = !string.IsNullOrWhiteSpace(winDir) &&
                                            (path.StartsWith(Path.Combine(winDir, "System32"), StringComparison.OrdinalIgnoreCase) ||
                                             path.StartsWith(Path.Combine(winDir, "SysWOW64"), StringComparison.OrdinalIgnoreCase) ||
                                             path.StartsWith(Path.Combine(winDir, "WinSxS"), StringComparison.OrdinalIgnoreCase));

                        if (!targetPid.HasValue && isSystemCore)
                            continue;

                        if (!sigCache.TryGetValue(path, out var auth))
                        {
                            auth = File.Exists(path)
                                ? _forensics.VerifyAuthenticode(path)
                                : new AuthenticodeInfo { IsSigned = false, IsTrusted = false, Status = "Missing" };
                            sigCache[path] = auth;
                        }

                        string sigStatus = auth.IsSigned && auth.IsTrusted
                            ? "Signed"
                            : auth.IsSigned ? "Invalid" : "Unsigned";

                        var lowerPath = path.ToLowerInvariant();
                        bool inSuspiciousDir = SuspiciousDllFolders.Any(f => lowerPath.Contains(f));

                        string risk = "Low";
                        string reason = "Verified signed module.";

                        if (sigStatus == "Invalid")
                        {
                            risk = "Critical";
                            reason = "Module has an INVALID or tampered digital signature!";
                        }
                        else if (sigStatus == "Unsigned" && inSuspiciousDir)
                        {
                            risk = "Critical";
                            reason = "Unsigned DLL loaded from user-writable/temp directory (classic DLL sideloading/injection pattern).";
                        }
                        else if (sigStatus == "Unsigned")
                        {
                            risk = "High";
                            reason = "Unsigned DLL loaded into live process memory.";
                        }
                        else if (inSuspiciousDir)
                        {
                            risk = "Medium";
                            reason = "Module loaded from temporary/user-writable directory.";
                        }

                        if (!targetPid.HasValue && risk == "Low")
                            continue;

                        long size = 0;
                        try { size = new FileInfo(path).Length; } catch { }

                        results.Add(new ProcessDllInfo
                        {
                            ProcessId = pid,
                            ProcessName = procName,
                            ModuleName = mod.ModuleName ?? Path.GetFileName(path),
                            FilePath = path,
                            SizeBytes = size,
                            SignatureStatus = sigStatus,
                            Publisher = auth.Subject,
                            RiskLevel = risk,
                            RiskReason = reason
                        });
                    }
                }
                catch { }
                finally
                {
                    try { proc.Dispose(); } catch { }
                }
            }
        }, ct).ConfigureAwait(false);

        var ordered = results
            .OrderByDescending(m => RiskWeight(m.RiskLevel))
            .ThenBy(m => m.ProcessName, StringComparer.OrdinalIgnoreCase)
            .Take(200)
            .ToList();

        var report = new ProcessDllAuditReport
        {
            AuditedAt = DateTimeOffset.UtcNow,
            ProcessesScanned = processesScanned,
            ModulesInspected = totalModulesInspected,
            UnsignedCount = ordered.Count(m => m.SignatureStatus is "Unsigned" or "Invalid"),
            SuspiciousPathCount = ordered.Count(m => m.RiskLevel is "High" or "Critical"),
            Modules = ordered
        };

        return OperationResult<ProcessDllAuditReport>.Ok(
            report,
            $"Inspected {totalModulesInspected} modules across {processesScanned} process(es): {report.UnsignedCount} unsigned/invalid flagged.");
    }

    private static int RiskWeight(string risk) => risk switch
    {
        "Critical" => 4,
        "High" => 3,
        "Medium" => 2,
        _ => 1
    };
}
