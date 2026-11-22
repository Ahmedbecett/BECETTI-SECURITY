using System.Security.Cryptography;
using System.Text.Json;
using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

public interface IFileIntegrityMonitorService : IDisposable
{
    bool IsWatching { get; }
    event EventHandler<FimViolationAlert>? IntegrityViolation;

    Task<IReadOnlyList<FimBaselineEntry>> ListTrackedFilesAsync(CancellationToken ct = default);
    Task<OperationResult<FimBaselineEntry>> TrackFileAsync(string filePath, CancellationToken ct = default);
    Task<OperationResult> UntrackFileAsync(string filePath, CancellationToken ct = default);
    Task<OperationResult<FimCheckReport>> VerifyAllAsync(CancellationToken ct = default);
    Task<OperationResult> RebaselineFileAsync(string filePath, CancellationToken ct = default);
    Task<OperationResult> StartWatchingAsync(CancellationToken ct = default);
    OperationResult StopWatching();
}

/// <summary>
/// Real File Integrity Monitor (FIM):
/// hashes sensitive user/system files with SHA-256, persists the baseline locally,
/// verifies on demand or watches in real time via FileSystemWatcher to detect any byte-level tampering.
/// </summary>
public sealed class FileIntegrityMonitorService : IFileIntegrityMonitorService
{
    private readonly string _storePath;
    private readonly SemaphoreSlim _lock = new(1, 1);
    private readonly List<FileSystemWatcher> _watchers = new();
    private Dictionary<string, FimBaselineEntry> _tracked = new(StringComparer.OrdinalIgnoreCase);

    public FileIntegrityMonitorService(ISettingsService? settings = null, string? customStorePath = null)
    {
        if (!string.IsNullOrWhiteSpace(customStorePath))
        {
            _storePath = customStorePath;
        }
        else
        {
            var dir = settings?.DataDirectory ?? Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "BecettiSecurity");
            _storePath = Path.Combine(dir, "fim-baseline.json");
        }
    }

    public bool IsWatching => _watchers.Count > 0;
    public event EventHandler<FimViolationAlert>? IntegrityViolation;

    public async Task<IReadOnlyList<FimBaselineEntry>> ListTrackedFilesAsync(CancellationToken ct = default)
    {
        await _lock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            LoadUnlocked();
            return _tracked.Values.OrderBy(e => e.FilePath, StringComparer.OrdinalIgnoreCase).ToList();
        }
        finally { _lock.Release(); }
    }

    public async Task<OperationResult<FimBaselineEntry>> TrackFileAsync(string filePath, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
            return OperationResult<FimBaselineEntry>.Fail("Selected file does not exist.", "FILE_NOT_FOUND");

        var fullPath = Path.GetFullPath(filePath);
        string sha256;
        long size;
        try
        {
            var fi = new FileInfo(fullPath);
            size = fi.Length;
            sha256 = await ComputeSha256Async(fullPath, ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            return OperationResult<FimBaselineEntry>.Fail($"Could not hash file: {ex.Message}", "HASH_ERROR");
        }

        var entry = new FimBaselineEntry
        {
            FilePath = fullPath,
            BaselineSha256 = sha256,
            BaselineSizeBytes = size,
            BaselineCreatedAt = DateTimeOffset.UtcNow
        };

        await _lock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            LoadUnlocked();
            _tracked[fullPath] = entry;
            SaveUnlocked();
        }
        finally { _lock.Release(); }

        if (IsWatching)
            await StartWatchingAsync(ct).ConfigureAwait(false);

        return OperationResult<FimBaselineEntry>.Ok(entry, $"Tracking '{Path.GetFileName(fullPath)}' (SHA-256: {sha256[..12]}...).");
    }

    public async Task<OperationResult> UntrackFileAsync(string filePath, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(filePath))
            return OperationResult.Fail("File path is required.", "INVALID_PATH");

        var fullPath = Path.GetFullPath(filePath);
        await _lock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            LoadUnlocked();
            if (!_tracked.Remove(fullPath))
                return OperationResult.Fail("File is not currently tracked.", "NOT_TRACKED");
            SaveUnlocked();
        }
        finally { _lock.Release(); }

        return OperationResult.Ok($"Removed '{Path.GetFileName(fullPath)}' from File Integrity Monitor.");
    }

    public Task<OperationResult> RebaselineFileAsync(string filePath, CancellationToken ct = default) =>
        TrackFileAsync(filePath, ct).ContinueWith(
            t => t.Result.Success
                ? OperationResult.Ok($"Updated SHA-256 baseline for '{Path.GetFileName(filePath)}'.")
                : OperationResult.Fail(t.Result.Message, t.Result.ErrorCode),
            ct);

    public async Task<OperationResult<FimCheckReport>> VerifyAllAsync(CancellationToken ct = default)
    {
        List<FimBaselineEntry> snapshot;
        await _lock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            LoadUnlocked();
            snapshot = _tracked.Values.OrderBy(v => v.FilePath, StringComparer.OrdinalIgnoreCase).ToList();
        }
        finally { _lock.Release(); }

        var items = new List<FimCheckItem>();
        int intact = 0, modified = 0, missing = 0;

        foreach (var entry in snapshot)
        {
            ct.ThrowIfCancellationRequested();
            if (!File.Exists(entry.FilePath))
            {
                missing++;
                items.Add(new FimCheckItem
                {
                    FilePath = entry.FilePath,
                    BaselineSha256 = entry.BaselineSha256,
                    CurrentSha256 = string.Empty,
                    Status = "Missing",
                    Detail = "File was deleted or moved since baseline!"
                });
                continue;
            }

            try
            {
                var actual = await ComputeSha256Async(entry.FilePath, ct).ConfigureAwait(false);
                if (string.Equals(actual, entry.BaselineSha256, StringComparison.OrdinalIgnoreCase))
                {
                    intact++;
                    items.Add(new FimCheckItem
                    {
                        FilePath = entry.FilePath,
                        BaselineSha256 = entry.BaselineSha256,
                        CurrentSha256 = actual,
                        Status = "Intact",
                        Detail = $"SHA-256 matches ({actual[..12]}...)"
                    });
                }
                else
                {
                    modified++;
                    items.Add(new FimCheckItem
                    {
                        FilePath = entry.FilePath,
                        BaselineSha256 = entry.BaselineSha256,
                        CurrentSha256 = actual,
                        Status = "Modified",
                        Detail = $"HASH MISMATCH! Expected {entry.BaselineSha256[..10]}..., got {actual[..10]}..."
                    });
                }
            }
            catch (Exception ex)
            {
                items.Add(new FimCheckItem
                {
                    FilePath = entry.FilePath,
                    BaselineSha256 = entry.BaselineSha256,
                    Status = "Error",
                    Detail = ex.Message
                });
            }
        }

        var report = new FimCheckReport
        {
            CheckedAt = DateTimeOffset.UtcNow,
            TotalTracked = snapshot.Count,
            IntactCount = intact,
            ModifiedCount = modified,
            MissingCount = missing,
            Items = items
        };

        return OperationResult<FimCheckReport>.Ok(
            report,
            (modified > 0 || missing > 0)
                ? $"INTEGRITY ALERT: {modified} modified, {missing} missing out of {snapshot.Count} tracked file(s)."
                : $"All {intact} tracked file(s) are intact (SHA-256 verified).");
    }

    public async Task<OperationResult> StartWatchingAsync(CancellationToken ct = default)
    {
        StopWatching();

        List<string> dirs;
        await _lock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            LoadUnlocked();
            dirs = _tracked.Keys
                .Select(Path.GetDirectoryName)
                .Where(d => !string.IsNullOrWhiteSpace(d) && Directory.Exists(d))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Cast<string>()
                .ToList();
        }
        finally { _lock.Release(); }

        foreach (var dir in dirs)
        {
            try
            {
                var fsw = new FileSystemWatcher(dir)
                {
                    NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.Size | NotifyFilters.FileName,
                    EnableRaisingEvents = true
                };
                fsw.Changed += OnFsEvent;
                fsw.Deleted += OnFsEvent;
                fsw.Renamed += OnRenamedEvent;
                _watchers.Add(fsw);
            }
            catch { }
        }

        return OperationResult.Ok($"File Integrity Monitor watching {_tracked.Count} file(s) across {_watchers.Count} folder(s).");
    }

    public OperationResult StopWatching()
    {
        foreach (var w in _watchers)
        {
            try
            {
                w.EnableRaisingEvents = false;
                w.Dispose();
            }
            catch { }
        }
        _watchers.Clear();
        return OperationResult.Ok("File Integrity Monitor stopped.");
    }

    private void OnFsEvent(object sender, FileSystemEventArgs e) => CheckTrackedPath(e.FullPath, e.ChangeType.ToString());
    private void OnRenamedEvent(object sender, RenamedEventArgs e) => CheckTrackedPath(e.OldFullPath, $"Renamed to {e.Name}");

    private void CheckTrackedPath(string fullPath, string changeType)
    {
        try
        {
            FimBaselineEntry? baseline;
            lock (_tracked)
            {
                if (!_tracked.TryGetValue(fullPath, out baseline))
                    return;
            }

            Thread.Sleep(120);
            string actual = File.Exists(fullPath) ? ComputeSha256Sync(fullPath) : "MISSING";
            if (string.Equals(actual, baseline.BaselineSha256, StringComparison.OrdinalIgnoreCase))
                return;

            IntegrityViolation?.Invoke(this, new FimViolationAlert
            {
                Timestamp = DateTimeOffset.UtcNow,
                FilePath = fullPath,
                ChangeType = changeType,
                ExpectedSha256 = baseline.BaselineSha256,
                ActualSha256 = actual
            });
        }
        catch { }
    }

    private void LoadUnlocked()
    {
        if (!File.Exists(_storePath)) return;
        try
        {
            var json = File.ReadAllText(_storePath);
            var list = JsonSerializer.Deserialize<List<FimBaselineEntry>>(json);
            if (list is not null)
            {
                _tracked = list.ToDictionary(x => x.FilePath, StringComparer.OrdinalIgnoreCase);
            }
        }
        catch { }
    }

    private void SaveUnlocked()
    {
        var dir = Path.GetDirectoryName(_storePath);
        if (!string.IsNullOrWhiteSpace(dir)) Directory.CreateDirectory(dir);
        var json = JsonSerializer.Serialize(_tracked.Values.ToList(), new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(_storePath, json);
    }

    private static async Task<string> ComputeSha256Async(string path, CancellationToken ct)
    {
        await using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        return Convert.ToHexString(await SHA256.HashDataAsync(fs, ct).ConfigureAwait(false));
    }

    private static string ComputeSha256Sync(string path)
    {
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        return Convert.ToHexString(SHA256.HashData(fs));
    }

    public void Dispose()
    {
        StopWatching();
        _lock.Dispose();
    }
}
