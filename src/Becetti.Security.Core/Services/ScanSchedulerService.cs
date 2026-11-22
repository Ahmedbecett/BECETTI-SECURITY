using System.Text.Json;
using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

public interface IScanSchedulerService : IDisposable
{
    bool IsRunning { get; }
    DateTimeOffset? NextRunUtc { get; }
    event EventHandler<ScheduledScanResult>? ScanCompleted;

    void Start();
    void Stop();
    Task<OperationResult<ScheduledScanResult>> RunScheduledAuditNowAsync(CancellationToken ct = default);
    Task<OperationResult<string>> ExportPolicyAsync(string? destinationPath = null, CancellationToken ct = default);
    Task<OperationResult> ImportPolicyAsync(string sourcePath, CancellationToken ct = default);
}

/// <summary>
/// Real Automated Scan Scheduler &amp; Security Policy Backup/Restore Service:
/// periodically runs Native YARA Quick Scan + Windows Hardening Audit on the configured
/// interval (daily/weekly), logs real results to EventLogService, and exports/imports
/// BECETTI SECURITY shield policies as portable JSON. Zero simulation.
/// </summary>
public sealed class ScanSchedulerService : IScanSchedulerService
{
    private readonly ISettingsService _settings;
    private readonly IYaraEngineService _yara;
    private readonly IWindowsHardeningService _hardening;
    private readonly IEventLogService _events;

    private CancellationTokenSource? _cts;
    private readonly object _lock = new();

    public bool IsRunning { get; private set; }
    public DateTimeOffset? NextRunUtc { get; private set; }
    public event EventHandler<ScheduledScanResult>? ScanCompleted;

    public ScanSchedulerService(
        ISettingsService settings,
        IYaraEngineService yara,
        IWindowsHardeningService hardening,
        IEventLogService events)
    {
        _settings = settings;
        _yara = yara;
        _hardening = hardening;
        _events = events;
    }

    public void Start()
    {
        lock (_lock)
        {
            if (IsRunning) return;
            _cts = new CancellationTokenSource();
            IsRunning = true;
            var token = _cts.Token;
            _ = Task.Run(() => LoopAsync(token), token);
        }
    }

    public void Stop()
    {
        lock (_lock)
        {
            IsRunning = false;
            NextRunUtc = null;
            try { _cts?.Cancel(); } catch { }
            try { _cts?.Dispose(); } catch { }
            _cts = null;
        }
    }

    private async Task LoopAsync(CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested)
            {
                if (_settings.Current.ScheduledScanEnabled)
                {
                    int intervalHours = Math.Clamp(_settings.Current.ScheduledScanIntervalHours, 1, 720);
                    var lastRun = _settings.Current.LastScheduledScanUtc ?? DateTimeOffset.MinValue;
                    var dueAt = lastRun == DateTimeOffset.MinValue
                        ? DateTimeOffset.UtcNow.AddMinutes(5)
                        : lastRun.AddHours(intervalHours);
                    NextRunUtc = dueAt;

                    if (DateTimeOffset.UtcNow >= dueAt)
                    {
                        await RunScheduledAuditNowAsync(ct).ConfigureAwait(false);
                    }
                }
                else
                {
                    NextRunUtc = null;
                }

                await Task.Delay(TimeSpan.FromMinutes(10), ct).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) { }
        catch { }
    }

    public async Task<OperationResult<ScheduledScanResult>> RunScheduledAuditNowAsync(CancellationToken ct = default)
    {
        int hardeningScore = 0;
        int yaraThreats = 0;

        try
        {
            var hardRes = await _hardening.AuditAsync(ct).ConfigureAwait(false);
            if (hardRes.Success && hardRes.Value is not null)
                hardeningScore = hardRes.Value.ScorePercent;

            // Scan Downloads folder if it exists and YARA is ready
            var downloads = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
            if (Directory.Exists(downloads))
            {
                var yaraRes = await _yara.ScanAsync(downloads, recursive: false, ct: ct).ConfigureAwait(false);
                if (yaraRes.Success && yaraRes.Value is not null)
                    yaraThreats = yaraRes.Value.Matches.Count;
            }

            _settings.Current.LastScheduledScanUtc = DateTimeOffset.UtcNow;
            await _settings.SaveAsync(ct).ConfigureAwait(false);

            var summary = $"Scheduled Audit completed: Hardening {hardeningScore}%, YARA threats found: {yaraThreats}.";
            var result = new ScheduledScanResult
            {
                ExecutedAt = DateTimeOffset.UtcNow,
                HardeningScore = hardeningScore,
                YaraThreatsFound = yaraThreats,
                Summary = summary
            };

            await _events.RecordAsync("ScheduledAudit", summary, yaraThreats == 0).ConfigureAwait(false);
            ScanCompleted?.Invoke(this, result);

            return OperationResult<ScheduledScanResult>.Ok(result, summary);
        }
        catch (Exception ex)
        {
            await _events.RecordAsync("ScheduledAudit", $"Scheduled audit error: {ex.Message}", false).ConfigureAwait(false);
            return OperationResult<ScheduledScanResult>.Fail($"Scheduled audit failed: {ex.Message}", "SCHEDULE_ERROR");
        }
    }

    public async Task<OperationResult<string>> ExportPolicyAsync(string? destinationPath = null, CancellationToken ct = default)
    {
        try
        {
            var target = destinationPath;
            if (string.IsNullOrWhiteSpace(target))
            {
                var dir = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                    "BECETTI-SECURITY",
                    "Policies");
                Directory.CreateDirectory(dir);
                target = Path.Combine(dir, $"becetti-policy-{DateTime.UtcNow:yyyyMMdd-HHmmss}.json");
            }

            var s = _settings.Current;
            var policy = new SecurityPolicyDocument
            {
                ExportedAtUtc = DateTimeOffset.UtcNow,
                Language = s.Language,
                RealTimeYaraGuardEnabled = s.RealTimeYaraGuardEnabled,
                RealTimeYaraAutoQuarantine = s.RealTimeYaraAutoQuarantine,
                RansomwareCanaryEnabled = s.RansomwareCanaryEnabled,
                ClipboardGuardEnabled = s.ClipboardGuardEnabled,
                UsbAutoScanEnabled = s.UsbAutoScanEnabled,
                HostsGuardEnabled = s.HostsGuardEnabled,
                FimAutoWatchEnabled = s.FimAutoWatchEnabled,
                MinimizeToTrayOnClose = s.MinimizeToTrayOnClose,
                ScheduledScanEnabled = s.ScheduledScanEnabled,
                ScheduledScanIntervalHours = s.ScheduledScanIntervalHours,
                YaraAutoUpdateEnabled = s.YaraAutoUpdateEnabled,
                YaraAutoUpdateIntervalHours = s.YaraAutoUpdateIntervalHours,
                CriticalAlertNotificationsEnabled = s.CriticalAlertNotificationsEnabled
            };

            var json = JsonSerializer.Serialize(policy, new JsonSerializerOptions { WriteIndented = true });
            await File.WriteAllTextAsync(target, json, ct).ConfigureAwait(false);
            return OperationResult<string>.Ok(target, $"Security policy exported to {target}");
        }
        catch (Exception ex)
        {
            return OperationResult<string>.Fail($"Policy export failed: {ex.Message}", "EXPORT_ERROR");
        }
    }

    public async Task<OperationResult> ImportPolicyAsync(string sourcePath, CancellationToken ct = default)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(sourcePath) || !File.Exists(sourcePath))
                return OperationResult.Fail("Policy file not found.", "NOT_FOUND");

            var json = await File.ReadAllTextAsync(sourcePath, ct).ConfigureAwait(false);
            var policy = JsonSerializer.Deserialize<SecurityPolicyDocument>(json);
            if (policy is null)
                return OperationResult.Fail("Invalid security policy JSON file.", "INVALID_JSON");

            var s = _settings.Current;
            if (!string.IsNullOrWhiteSpace(policy.Language)) s.Language = policy.Language;
            s.RealTimeYaraGuardEnabled = policy.RealTimeYaraGuardEnabled;
            s.RealTimeYaraAutoQuarantine = policy.RealTimeYaraAutoQuarantine;
            s.RansomwareCanaryEnabled = policy.RansomwareCanaryEnabled;
            s.ClipboardGuardEnabled = policy.ClipboardGuardEnabled;
            s.UsbAutoScanEnabled = policy.UsbAutoScanEnabled;
            s.HostsGuardEnabled = policy.HostsGuardEnabled;
            s.FimAutoWatchEnabled = policy.FimAutoWatchEnabled;
            s.MinimizeToTrayOnClose = policy.MinimizeToTrayOnClose;
            s.ScheduledScanEnabled = policy.ScheduledScanEnabled;
            s.ScheduledScanIntervalHours = Math.Clamp(policy.ScheduledScanIntervalHours, 1, 720);
            s.YaraAutoUpdateEnabled = policy.YaraAutoUpdateEnabled;
            s.YaraAutoUpdateIntervalHours = Math.Clamp(policy.YaraAutoUpdateIntervalHours, 1, 168);
            s.CriticalAlertNotificationsEnabled = policy.CriticalAlertNotificationsEnabled;

            await _settings.SaveAsync(ct).ConfigureAwait(false);
            await _events.RecordAsync("PolicyImport", $"Imported BECETTI SECURITY policy from {Path.GetFileName(sourcePath)}", true).ConfigureAwait(false);
            return OperationResult.Ok("Security policy imported and saved successfully.");
        }
        catch (Exception ex)
        {
            return OperationResult.Fail($"Policy import failed: {ex.Message}", "IMPORT_ERROR");
        }
    }

    public void Dispose() => Stop();

    private sealed class SecurityPolicyDocument
    {
        public string Schema { get; set; } = "becetti-security-policy/v1";
        public DateTimeOffset ExportedAtUtc { get; set; }
        public string Language { get; set; } = "en";
        public bool RealTimeYaraGuardEnabled { get; set; }
        public bool RealTimeYaraAutoQuarantine { get; set; }
        public bool RansomwareCanaryEnabled { get; set; }
        public bool ClipboardGuardEnabled { get; set; }
        public bool UsbAutoScanEnabled { get; set; }
        public bool HostsGuardEnabled { get; set; }
        public bool FimAutoWatchEnabled { get; set; }
        public bool MinimizeToTrayOnClose { get; set; }
        public bool ScheduledScanEnabled { get; set; }
        public int ScheduledScanIntervalHours { get; set; } = 24;
        public bool YaraAutoUpdateEnabled { get; set; }
        public int YaraAutoUpdateIntervalHours { get; set; } = 24;
        public bool CriticalAlertNotificationsEnabled { get; set; } = true;
    }
}
