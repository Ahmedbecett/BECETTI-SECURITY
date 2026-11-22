using System.Security.Cryptography;
using System.Text;
using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

/// <summary>
/// Real Ransomware Canary / Honeypot Guard:
/// Places hidden decoy files with verified SHA-256 fingerprints into monitored folders
/// and watches them in real time via FileSystemWatcher. Any unauthorized modification,
/// encryption, renaming, or deletion immediately raises a critical CanaryTripped alert.
/// </summary>
public interface IRansomwareCanaryService : IDisposable
{
    bool IsArmed { get; }
    IReadOnlyList<CanaryFileStatus> ActiveCanaries { get; }
    IReadOnlyList<CanaryAlertEvent> RecentAlerts { get; }

    event EventHandler<CanaryAlertEvent>? CanaryTripped;

    Task<OperationResult<IReadOnlyList<CanaryFileStatus>>> ArmAsync(IEnumerable<string>? targetFolders = null, CancellationToken ct = default);
    Task<OperationResult<IReadOnlyList<CanaryFileStatus>>> VerifyIntegrityAsync(CancellationToken ct = default);
    void Disarm(bool removeDecoyFiles = true);
}

public sealed class RansomwareCanaryService : IRansomwareCanaryService
{
    private const string CanaryPrefix = ".becetti_canary_";
    private readonly List<FileSystemWatcher> _watchers = new();
    private readonly Dictionary<string, CanaryRecord> _canaries = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<CanaryAlertEvent> _alerts = new();
    private readonly object _sync = new();

    public bool IsArmed { get; private set; }

    public IReadOnlyList<CanaryFileStatus> ActiveCanaries
    {
        get
        {
            lock (_sync)
            {
                return _canaries.Values.Select(c => new CanaryFileStatus
                {
                    FolderPath = c.FolderPath,
                    FilePath = c.FilePath,
                    ExpectedSha256 = c.ExpectedSha256,
                    IsIntact = c.IsIntact,
                    StatusText = c.StatusText
                }).ToList();
            }
        }
    }

    public IReadOnlyList<CanaryAlertEvent> RecentAlerts
    {
        get
        {
            lock (_sync)
            {
                return _alerts.AsEnumerable().Reverse().ToList();
            }
        }
    }

    public event EventHandler<CanaryAlertEvent>? CanaryTripped;

    public static IReadOnlyList<string> GetDefaultFolders()
    {
        var dirs = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            Environment.GetFolderPath(Environment.SpecialFolder.MyPictures),
            Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory)
        };
        return dirs.Where(d => !string.IsNullOrWhiteSpace(d) && Directory.Exists(d))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    public async Task<OperationResult<IReadOnlyList<CanaryFileStatus>>> ArmAsync(IEnumerable<string>? targetFolders = null, CancellationToken ct = default)
    {
        var dirs = (targetFolders is not null
                ? targetFolders.Where(d => !string.IsNullOrWhiteSpace(d) && Directory.Exists(d))
                : GetDefaultFolders())
            .Select(Path.GetFullPath)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (dirs.Count == 0)
            return OperationResult<IReadOnlyList<CanaryFileStatus>>.Fail("No valid directories found for canary deployment.", "NO_FOLDERS");

        Disarm(removeDecoyFiles: false);

        var deployed = new List<CanaryRecord>();
        foreach (var dir in dirs)
        {
            try
            {
                var canaryPath = Path.Combine(dir, $"{CanaryPrefix}guard.txt");
                var payload = Encoding.UTF8.GetBytes(
                    $"BECETTI SECURITY Ransomware Canary Decoy\n" +
                    $"Do not edit or delete this protected sentinel file.\n" +
                    $"Folder: {dir}\n" +
                    $"FingerprintSeed: {Guid.NewGuid():N}\n");

                if (File.Exists(canaryPath))
                {
                    try { File.SetAttributes(canaryPath, FileAttributes.Normal); } catch { }
                }

                await File.WriteAllBytesAsync(canaryPath, payload, ct).ConfigureAwait(false);
                try { File.SetAttributes(canaryPath, FileAttributes.Hidden); } catch { }

                var sha = Convert.ToHexString(SHA256.HashData(payload)).ToLowerInvariant();
                deployed.Add(new CanaryRecord(dir, canaryPath, sha));
            }
            catch
            {
                // Skip unwritable folders
            }
        }

        if (deployed.Count == 0)
            return OperationResult<IReadOnlyList<CanaryFileStatus>>.Fail("Could not create canary decoy files in any target folder.", "CANARY_CREATE_FAILED");

        lock (_sync)
        {
            foreach (var rec in deployed)
            {
                _canaries[rec.FilePath] = rec;
                var watcher = new FileSystemWatcher(rec.FolderPath, Path.GetFileName(rec.FilePath))
                {
                    IncludeSubdirectories = false,
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size | NotifyFilters.Attributes,
                    EnableRaisingEvents = true
                };
                watcher.Changed += OnCanaryChanged;
                watcher.Deleted += OnCanaryDeleted;
                watcher.Renamed += OnCanaryRenamed;
                _watchers.Add(watcher);
            }
            IsArmed = true;
        }

        return OperationResult<IReadOnlyList<CanaryFileStatus>>.Ok(
            ActiveCanaries,
            $"Ransomware Canary Guard armed with {deployed.Count} hidden decoy file(s).");
    }

    public async Task<OperationResult<IReadOnlyList<CanaryFileStatus>>> VerifyIntegrityAsync(CancellationToken ct = default)
    {
        List<CanaryRecord> snapshot;
        lock (_sync)
            snapshot = _canaries.Values.ToList();

        foreach (var rec in snapshot)
        {
            if (!File.Exists(rec.FilePath))
            {
                MarkTripped(rec, "Deleted", "Canary file was deleted or renamed — possible ransomware activity!");
                continue;
            }

            try
            {
                var currentBytes = await File.ReadAllBytesAsync(rec.FilePath, ct).ConfigureAwait(false);
                var currentSha = Convert.ToHexString(SHA256.HashData(currentBytes)).ToLowerInvariant();
                if (!string.Equals(currentSha, rec.ExpectedSha256, StringComparison.OrdinalIgnoreCase))
                {
                    var entropy = FileForensicsService.ComputeShannonEntropy(currentBytes);
                    MarkTripped(rec, "Modified",
                        $"Canary SHA-256 changed! Current Shannon entropy: {entropy:F2}/8.00 (expected untouched decoy).");
                }
            }
            catch (Exception ex)
            {
                MarkTripped(rec, "Unreadable", $"Canary file could not be read: {ex.Message}");
            }
        }

        return OperationResult<IReadOnlyList<CanaryFileStatus>>.Ok(ActiveCanaries, "Canary integrity check complete.");
    }

    public void Disarm(bool removeDecoyFiles = true)
    {
        List<string> pathsToRemove;
        lock (_sync)
        {
            foreach (var w in _watchers)
            {
                try
                {
                    w.EnableRaisingEvents = false;
                    w.Changed -= OnCanaryChanged;
                    w.Deleted -= OnCanaryDeleted;
                    w.Renamed -= OnCanaryRenamed;
                    w.Dispose();
                }
                catch { }
            }
            _watchers.Clear();
            pathsToRemove = _canaries.Keys.ToList();
            _canaries.Clear();
            IsArmed = false;
        }

        if (removeDecoyFiles)
        {
            foreach (var p in pathsToRemove)
            {
                try
                {
                    if (File.Exists(p))
                    {
                        File.SetAttributes(p, FileAttributes.Normal);
                        File.Delete(p);
                    }
                }
                catch { }
            }
        }
    }

    private void OnCanaryChanged(object sender, FileSystemEventArgs e)
    {
        CanaryRecord? rec;
        lock (_sync)
            _canaries.TryGetValue(e.FullPath, out rec);
        if (rec is null)
            return;

        try
        {
            var bytes = File.ReadAllBytes(rec.FilePath);
            var sha = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
            if (string.Equals(sha, rec.ExpectedSha256, StringComparison.OrdinalIgnoreCase))
                return;

            var entropy = FileForensicsService.ComputeShannonEntropy(bytes);
            MarkTripped(rec, "Modified/Encrypted",
                $"Unauthorized modification detected on canary file! Entropy: {entropy:F2}/8.00.");
        }
        catch (Exception ex)
        {
            MarkTripped(rec, "Locked/Modified", $"Canary file touched and locked: {ex.Message}");
        }
    }

    private void OnCanaryDeleted(object sender, FileSystemEventArgs e)
    {
        CanaryRecord? rec;
        lock (_sync)
            _canaries.TryGetValue(e.FullPath, out rec);
        if (rec is not null)
            MarkTripped(rec, "Deleted", "Canary file was deleted unexpectedly.");
    }

    private void OnCanaryRenamed(object sender, RenamedEventArgs e)
    {
        CanaryRecord? rec;
        lock (_sync)
            _canaries.TryGetValue(e.OldFullPath, out rec);
        if (rec is not null)
            MarkTripped(rec, "Renamed", $"Canary file was renamed to '{Path.GetFileName(e.FullPath)}' (classic ransomware extension append!).");
    }

    private void MarkTripped(CanaryRecord rec, string changeType, string details)
    {
        var alert = new CanaryAlertEvent
        {
            DetectedAt = DateTimeOffset.UtcNow,
            FilePath = rec.FilePath,
            ChangeType = changeType,
            Details = details
        };

        lock (_sync)
        {
            rec.IsIntact = false;
            rec.StatusText = $"TRIPPED ({changeType})";
            _alerts.Add(alert);
            if (_alerts.Count > 50)
                _alerts.RemoveAt(0);
        }

        CanaryTripped?.Invoke(this, alert);
    }

    public void Dispose() => Disarm(removeDecoyFiles: false);

    private sealed class CanaryRecord
    {
        public CanaryRecord(string folderPath, string filePath, string expectedSha256)
        {
            FolderPath = folderPath;
            FilePath = filePath;
            ExpectedSha256 = expectedSha256;
        }

        public string FolderPath { get; }
        public string FilePath { get; }
        public string ExpectedSha256 { get; }
        public bool IsIntact { get; set; } = true;
        public string StatusText { get; set; } = "Armed & Intact";
    }
}
