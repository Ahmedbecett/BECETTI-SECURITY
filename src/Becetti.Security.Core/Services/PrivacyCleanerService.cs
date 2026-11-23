using System.Diagnostics;
using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

public interface IPrivacyCleanerService
{
    Task<OperationResult<IReadOnlyList<PrivacyTraceCategory>>> ScanReclaimableTracesAsync(CancellationToken ct = default);
    Task<OperationResult<PrivacyCleanResult>> CleanSelectedCategoriesAsync(IEnumerable<PrivacyTraceCategory> categories, bool flushDnsCache = true, CancellationToken ct = default);
}

/// <summary>
/// #3: Deep Privacy &amp; Digital Traces Cleaner.
/// Audits real reclaimable Windows Temp, Recent shortcuts, Windows Error Reporting dumps,
/// and Browser cache folders (Chrome, Edge, Brave, Firefox) BEFORE deleting anything,
/// then safely removes only selected non-locked artifacts + optionally flushes DNS cache.
/// </summary>
public sealed class PrivacyCleanerService : IPrivacyCleanerService
{
    public async Task<OperationResult<IReadOnlyList<PrivacyTraceCategory>>> ScanReclaimableTracesAsync(CancellationToken ct = default)
    {
        var results = new List<PrivacyTraceCategory>();

        await Task.Run(() =>
        {
            var localApp = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

            results.Add(MeasureCategory("win-temp", "Windows User Temporary Files",
                "Temporary installer & application scratch files in %TEMP%",
                new[] { Path.GetTempPath() }, ct));

            results.Add(MeasureCategory("win-recent", "Windows Recent Files & JumpList Shortcuts",
                "Tracks recently opened documents and folders in Explorer",
                new[] { Path.Combine(appData, "Microsoft", "Windows", "Recent") }, ct));

            results.Add(MeasureCategory("win-wer", "Windows Error Reporting Crash Dumps",
                "Diagnostic reports and crash artifacts stored by Windows Error Reporting",
                new[] { Path.Combine(localApp, "Microsoft", "Windows", "WER") }, ct));

            results.Add(MeasureCategory("chrome-cache", "Google Chrome Disk & Code Cache",
                "Cached web assets and tracking resources (preserves passwords & bookmarks)",
                new[]
                {
                    Path.Combine(localApp, "Google", "Chrome", "User Data", "Default", "Cache", "Cache_Data"),
                    Path.Combine(localApp, "Google", "Chrome", "User Data", "Default", "Code Cache")
                }, ct));

            results.Add(MeasureCategory("edge-cache", "Microsoft Edge Disk & Code Cache",
                "Cached web assets and tracking resources (preserves passwords & bookmarks)",
                new[]
                {
                    Path.Combine(localApp, "Microsoft", "Edge", "User Data", "Default", "Cache", "Cache_Data"),
                    Path.Combine(localApp, "Microsoft", "Edge", "User Data", "Default", "Code Cache")
                }, ct));

            results.Add(MeasureCategory("brave-cache", "Brave Browser Disk Cache",
                "Cached web assets (preserves passwords & bookmarks)",
                new[]
                {
                    Path.Combine(localApp, "BraveSoftware", "Brave-Browser", "User Data", "Default", "Cache", "Cache_Data")
                }, ct));
        }, ct).ConfigureAwait(false);

        long totalBytes = results.Sum(r => r.TotalBytes);
        int totalFiles = results.Sum(r => r.FileCount);
        var msg = $"Found {totalFiles:N0} trace file(s) ({totalBytes / (1024.0 * 1024.0):F2} MB reclaimable) across {results.Count} privacy categories.";
        return OperationResult<IReadOnlyList<PrivacyTraceCategory>>.Ok(results, msg);
    }

    public async Task<OperationResult<PrivacyCleanResult>> CleanSelectedCategoriesAsync(
        IEnumerable<PrivacyTraceCategory> categories,
        bool flushDnsCache = true,
        CancellationToken ct = default)
    {
        var selected = (categories ?? Array.Empty<PrivacyTraceCategory>()).Where(c => c.IsSelected).ToList();
        int removed = 0;
        long bytesReclaimed = 0;
        int skipped = 0;

        await Task.Run(() =>
        {
            foreach (var cat in selected)
            {
                foreach (var dir in cat.TargetPaths)
                {
                    if (string.IsNullOrWhiteSpace(dir) || !Directory.Exists(dir)) continue;
                    foreach (var file in SafeEnumerateFiles(dir))
                    {
                        ct.ThrowIfCancellationRequested();
                        try
                        {
                            var fi = new FileInfo(file);
                            long len = fi.Exists ? fi.Length : 0;
                            fi.Delete();
                            removed++;
                            bytesReclaimed += len;
                        }
                        catch
                        {
                            skipped++;
                        }
                    }
                }
            }
        }, ct).ConfigureAwait(false);

        bool dnsFlushed = false;
        if (flushDnsCache && OperatingSystem.IsWindows())
            dnsFlushed = await TryFlushDnsAsync(ct).ConfigureAwait(false);

        var summary = $"Cleaned {removed:N0} file(s) ({bytesReclaimed / (1024.0 * 1024.0):F2} MB reclaimed, {skipped} locked file(s) skipped)" +
                      (dnsFlushed ? " + DNS cache flushed." : ".");

        return OperationResult<PrivacyCleanResult>.Ok(new PrivacyCleanResult
        {
            FilesRemoved = removed,
            BytesReclaimed = bytesReclaimed,
            DnsCacheFlushed = dnsFlushed,
            SkippedLockedFiles = skipped,
            Summary = summary
        }, summary);
    }

    private static PrivacyTraceCategory MeasureCategory(string id, string name, string desc, IReadOnlyList<string> paths, CancellationToken ct)
    {
        int count = 0;
        long bytes = 0;
        foreach (var dir in paths)
        {
            if (string.IsNullOrWhiteSpace(dir) || !Directory.Exists(dir)) continue;
            foreach (var file in SafeEnumerateFiles(dir))
            {
                if (ct.IsCancellationRequested) break;
                try
                {
                    bytes += new FileInfo(file).Length;
                    count++;
                }
                catch { }
            }
        }

        return new PrivacyTraceCategory
        {
            Id = id,
            Name = name,
            Description = desc,
            FileCount = count,
            TotalBytes = bytes,
            TargetPaths = paths
        };
    }

    private static IEnumerable<string> SafeEnumerateFiles(string root)
    {
        var stack = new Stack<string>();
        stack.Push(root);
        while (stack.Count > 0)
        {
            var cur = stack.Pop();
            string[] files;
            try { files = Directory.GetFiles(cur); }
            catch { continue; }
            foreach (var f in files) yield return f;

            string[] dirs;
            try { dirs = Directory.GetDirectories(cur); }
            catch { continue; }
            foreach (var d in dirs) stack.Push(d);
        }
    }

    private static async Task<bool> TryFlushDnsAsync(CancellationToken ct)
    {
        try
        {
            using var p = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "ipconfig.exe",
                    Arguments = "/flushdns",
                    UseShellExecute = false,
                    CreateNoWindow = true
                }
            };
            p.Start();
            await p.WaitForExitAsync(ct).ConfigureAwait(false);
            return p.ExitCode == 0;
        }
        catch { return false; }
    }
}
