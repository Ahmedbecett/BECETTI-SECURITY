using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

/// <summary>
/// Real USB Removable Drive Auto-Scanner:
/// Watches mounted removable drives and automatically launches a real local Native YARA
/// Engine scan whenever a USB flash drive is inserted.
/// </summary>
public interface IUsbAutoScanService : IDisposable
{
    bool IsEnabled { get; }
    IReadOnlyList<string> KnownRemovableDrives { get; }
    IReadOnlyList<UsbAutoScanEvent> RecentScans { get; }

    event EventHandler<UsbAutoScanEvent>? UsbScanCompleted;
    event EventHandler<UsbAutoScanEvent>? UsbThreatDetected;

    void Start();
    void Stop();
    Task<OperationResult<UsbAutoScanEvent>> ScanDriveNowAsync(string driveRoot, CancellationToken ct = default);
}

public sealed class UsbAutoScanService : IUsbAutoScanService
{
    private readonly IYaraEngineService _yara;
    private readonly List<UsbAutoScanEvent> _recentScans = new();
    private readonly HashSet<string> _knownDrives = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _sync = new();
    private CancellationTokenSource? _cts;

    public UsbAutoScanService(IYaraEngineService yara)
    {
        _yara = yara;
    }

    public bool IsEnabled => _cts is not null && !_cts.IsCancellationRequested;

    public IReadOnlyList<string> KnownRemovableDrives
    {
        get
        {
            lock (_sync)
                return _knownDrives.OrderBy(d => d, StringComparer.OrdinalIgnoreCase).ToList();
        }
    }

    public IReadOnlyList<UsbAutoScanEvent> RecentScans
    {
        get
        {
            lock (_sync)
                return _recentScans.AsEnumerable().Reverse().ToList();
        }
    }

    public event EventHandler<UsbAutoScanEvent>? UsbScanCompleted;
    public event EventHandler<UsbAutoScanEvent>? UsbThreatDetected;

    public void Start()
    {
        lock (_sync)
        {
            if (_cts is not null && !_cts.IsCancellationRequested)
                return;

            // Snapshot currently connected removable drives so we only auto-scan newly inserted ones
            _knownDrives.Clear();
            foreach (var root in GetReadyRemovableDriveRoots())
                _knownDrives.Add(root);

            _cts = new CancellationTokenSource();
            var token = _cts.Token;
            _ = Task.Run(() => PollLoopAsync(token), token);
        }
    }

    public void Stop()
    {
        lock (_sync)
        {
            if (_cts is not null)
            {
                try { _cts.Cancel(); } catch { }
                _cts.Dispose();
                _cts = null;
            }
        }
    }

    public async Task<OperationResult<UsbAutoScanEvent>> ScanDriveNowAsync(string driveRoot, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(driveRoot) || !Directory.Exists(driveRoot))
            return OperationResult<UsbAutoScanEvent>.Fail("Removable drive path is not accessible.", "DRIVE_NOT_READY");

        string label = string.Empty;
        try
        {
            var di = new DriveInfo(driveRoot);
            if (di.IsReady)
                label = di.VolumeLabel;
        }
        catch { }

        var scan = await _yara.ScanAsync(driveRoot, progress: null, ct).ConfigureAwait(false);
        if (!scan.Success || scan.Value is null)
            return OperationResult<UsbAutoScanEvent>.Fail($"USB YARA scan failed: {scan.Message}", scan.ErrorCode);

        var r = scan.Value;
        var ev = new UsbAutoScanEvent
        {
            Timestamp = DateTimeOffset.UtcNow,
            DriveRoot = driveRoot,
            VolumeLabel = label,
            FilesScanned = r.FilesScanned,
            MatchesFound = r.Matches.Count,
            Summary = r.ThreatFound
                ? $"ALERT on USB {driveRoot} ({label}): {r.Matches.Count} YARA match(es) across {r.FilesScanned} file(s)!"
                : $"USB {driveRoot} ({label}) clean ({r.FilesScanned} file(s) scanned by YARA)."
        };

        lock (_sync)
        {
            _recentScans.Add(ev);
            if (_recentScans.Count > 50)
                _recentScans.RemoveAt(0);
        }

        UsbScanCompleted?.Invoke(this, ev);
        if (ev.MatchesFound > 0)
            UsbThreatDetected?.Invoke(this, ev);

        return OperationResult<UsbAutoScanEvent>.Ok(ev, ev.Summary);
    }

    private async Task PollLoopAsync(CancellationToken ct)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(3));
        try
        {
            while (await timer.WaitForNextTickAsync(ct).ConfigureAwait(false))
            {
                var current = GetReadyRemovableDriveRoots();
                var newlyInserted = new List<string>();

                lock (_sync)
                {
                    foreach (var root in current)
                    {
                        if (_knownDrives.Add(root))
                            newlyInserted.Add(root);
                    }
                    _knownDrives.RemoveWhere(d => !current.Contains(d, StringComparer.OrdinalIgnoreCase));
                }

                foreach (var drive in newlyInserted)
                {
                    if (ct.IsCancellationRequested)
                        break;
                    await ScanDriveNowAsync(drive, ct).ConfigureAwait(false);
                }
            }
        }
        catch (OperationCanceledException)
        {
            // Clean shutdown
        }
    }

    private static List<string> GetReadyRemovableDriveRoots()
    {
        var list = new List<string>();
        try
        {
            foreach (var d in DriveInfo.GetDrives())
            {
                if (d.DriveType == DriveType.Removable && d.IsReady)
                    list.Add(d.RootDirectory.FullName);
            }
        }
        catch
        {
            // Ignore transient drive enumeration errors
        }
        return list;
    }

    public void Dispose() => Stop();
}
