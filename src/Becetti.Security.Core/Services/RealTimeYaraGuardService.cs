using System.Collections.Concurrent;
using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

/// <summary>
/// Real-time local file system guard powered by FileSystemWatcher + Native YARA Engine.
/// Watches Downloads, Desktop, Temp, and Startup (or custom folders) and immediately scans
/// newly created or modified files with yara64.exe, optionally auto-quarantining detections.
/// </summary>
public interface IRealTimeYaraGuardService : IDisposable
{
    bool IsRunning { get; }
    bool AutoQuarantineEnabled { get; set; }
    IReadOnlyList<string> MonitoredFolders { get; }
    IReadOnlyList<RealTimeGuardEvent> RecentEvents { get; }

    event EventHandler<RealTimeGuardEvent>? FileScanned;
    event EventHandler<RealTimeGuardEvent>? ThreatDetected;

    Task<OperationResult> StartAsync(IEnumerable<string>? customFolders = null, CancellationToken ct = default);
    void Stop();
}

public sealed class RealTimeYaraGuardService : IRealTimeYaraGuardService
{
    private const long MaxRealtimeScanBytes = 25 * 1024 * 1024; // 25 MB cap for instant watcher scans
    private readonly IYaraEngineService _yara;
    private readonly IQuarantineService _quarantine;
    private readonly ISettingsService _settings;

    private readonly List<FileSystemWatcher> _watchers = new();
    private readonly List<string> _monitoredFolders = new();
    private readonly ConcurrentDictionary<string, DateTimeOffset> _recentDebounce = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentQueue<RealTimeGuardEvent> _recentEvents = new();
    private readonly SemaphoreSlim _scanConcurrency = new(2, 2);
    private readonly object _sync = new();

    public RealTimeYaraGuardService(IYaraEngineService yara, IQuarantineService quarantine, ISettingsService settings)
    {
        _yara = yara;
        _quarantine = quarantine;
        _settings = settings;
    }

    public bool IsRunning { get; private set; }
    public bool AutoQuarantineEnabled { get; set; }
    public IReadOnlyList<string> MonitoredFolders => _monitoredFolders.AsReadOnly();
    public IReadOnlyList<RealTimeGuardEvent> RecentEvents => _recentEvents.Reverse().ToList();

    public event EventHandler<RealTimeGuardEvent>? FileScanned;
    public event EventHandler<RealTimeGuardEvent>? ThreatDetected;

    public static IReadOnlyList<string> GetDefaultSensitiveFolders()
    {
        var folders = new List<string>();
        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (!string.IsNullOrWhiteSpace(profile))
            folders.Add(Path.Combine(profile, "Downloads"));

        folders.Add(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory));
        folders.Add(Environment.GetFolderPath(Environment.SpecialFolder.Startup));
        folders.Add(Path.GetTempPath());

        return folders
            .Where(f => !string.IsNullOrWhiteSpace(f) && Directory.Exists(f))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    public async Task<OperationResult> StartAsync(IEnumerable<string>? customFolders = null, CancellationToken ct = default)
    {
        var init = await _yara.InitializeAsync(ct).ConfigureAwait(false);
        if (!init.Success || init.Value is null || !init.Value.IsAvailable)
            return OperationResult.Fail($"Cannot start Real-Time YARA Guard: {init.Message}", "YARA_UNAVAILABLE");

        var targets = (customFolders is not null
                ? customFolders.Where(f => !string.IsNullOrWhiteSpace(f) && Directory.Exists(f))
                : GetDefaultSensitiveFolders())
            .Select(Path.GetFullPath)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (targets.Count == 0)
            return OperationResult.Fail("No valid directories were found to monitor.", "NO_FOLDERS");

        lock (_sync)
        {
            StopUnlocked();
            foreach (var dir in targets)
            {
                try
                {
                    var watcher = new FileSystemWatcher(dir)
                    {
                        IncludeSubdirectories = false,
                        NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.CreationTime,
                        EnableRaisingEvents = true
                    };
                    watcher.Created += OnFileChanged;
                    watcher.Changed += OnFileChanged;
                    watcher.Renamed += OnFileRenamed;
                    _watchers.Add(watcher);
                    _monitoredFolders.Add(dir);
                }
                catch
                {
                    // Skip folders without watcher permission
                }
            }
            IsRunning = _watchers.Count > 0;
        }

        return IsRunning
            ? OperationResult.Ok($"Real-Time YARA Folder Guard active on {_monitoredFolders.Count} folder(s).")
            : OperationResult.Fail("Could not attach file watchers to any target folder.", "WATCHER_FAILED");
    }

    public void Stop()
    {
        lock (_sync)
        {
            StopUnlocked();
        }
    }

    private void StopUnlocked()
    {
        foreach (var w in _watchers)
        {
            try
            {
                w.EnableRaisingEvents = false;
                w.Created -= OnFileChanged;
                w.Changed -= OnFileChanged;
                w.Renamed -= OnFileRenamed;
                w.Dispose();
            }
            catch { }
        }
        _watchers.Clear();
        _monitoredFolders.Clear();
        IsRunning = false;
    }

    private void OnFileChanged(object sender, FileSystemEventArgs e) => EnqueueScan(e.FullPath);
    private void OnFileRenamed(object sender, RenamedEventArgs e) => EnqueueScan(e.FullPath);

    private void EnqueueScan(string fullPath)
    {
        if (!IsRunning || string.IsNullOrWhiteSpace(fullPath))
            return;

        // Ignore our own app data (quarantine/compiled rules/logs) and temporary download stubs
        var appDataRoot = Path.GetFullPath(_settings.DataDirectory);
        if (fullPath.StartsWith(appDataRoot, StringComparison.OrdinalIgnoreCase))
            return;

        var ext = Path.GetExtension(fullPath);
        if (ext.Equals(".crdownload", StringComparison.OrdinalIgnoreCase) ||
            ext.Equals(".part", StringComparison.OrdinalIgnoreCase) ||
            ext.Equals(".tmp", StringComparison.OrdinalIgnoreCase) ||
            ext.Equals(".bqtn", StringComparison.OrdinalIgnoreCase))
            return;

        var now = DateTimeOffset.UtcNow;
        if (_recentDebounce.TryGetValue(fullPath, out var last) && (now - last) < TimeSpan.FromSeconds(2))
            return;
        _recentDebounce[fullPath] = now;

        _ = Task.Run(() => ProcessFileAsync(fullPath));
    }

    private async Task ProcessFileAsync(string fullPath)
    {
        // Brief settle delay so writer finishes flushing bytes
        await Task.Delay(250).ConfigureAwait(false);

        if (!File.Exists(fullPath))
            return;

        try
        {
            var info = new FileInfo(fullPath);
            if (info.Length == 0 || info.Length > MaxRealtimeScanBytes)
                return;
        }
        catch
        {
            return;
        }

        await _scanConcurrency.WaitAsync().ConfigureAwait(false);
        try
        {
            if (!File.Exists(fullPath))
                return;

            var result = await _yara.ScanAsync(fullPath).ConfigureAwait(false);
            if (!result.Success || result.Value is null)
                return;

            var report = result.Value;
            bool threat = report.ThreatFound;
            bool quarantined = false;
            var rulesSummary = threat
                ? string.Join(", ", report.Matches.Select(m => m.RuleName).Distinct())
                : "Clean";

            if (threat && AutoQuarantineEnabled)
            {
                var first = report.Matches[0];
                var q = await _quarantine.QuarantineFileAsync(
                    fullPath,
                    first.RuleName,
                    first.Description,
                    "YARA Real-Time Guard").ConfigureAwait(false);
                quarantined = q.Success;
            }

            var ev = new RealTimeGuardEvent
            {
                Timestamp = DateTimeOffset.UtcNow,
                FilePath = fullPath,
                ThreatDetected = threat,
                AutoQuarantined = quarantined,
                MatchedRulesSummary = rulesSummary,
                Note = threat ? report.Matches[0].Description : "Scanned cleanly by YARA."
            };

            _recentEvents.Enqueue(ev);
            while (_recentEvents.Count > 100)
                _recentEvents.TryDequeue(out _);

            FileScanned?.Invoke(this, ev);
            if (threat)
                ThreatDetected?.Invoke(this, ev);
        }
        catch
        {
            // Never crash background watcher thread
        }
        finally
        {
            _scanConcurrency.Release();
        }
    }

    public void Dispose()
    {
        Stop();
        _scanConcurrency.Dispose();
    }
}
