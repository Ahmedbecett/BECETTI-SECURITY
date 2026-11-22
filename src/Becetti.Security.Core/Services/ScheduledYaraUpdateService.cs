using System.Text.Json;
using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

/// <summary>
/// Persisted background scheduler for automatic YARA rule updates from trusted repositories.
/// Every downloaded rule file is validated individually via yarac64.exe before activation.
/// </summary>
public interface IScheduledYaraUpdateService : IDisposable
{
    YaraUpdateScheduleConfig CurrentConfig { get; }
    bool IsBackgroundLoopRunning { get; }

    event EventHandler<string>? UpdateCompleted;

    Task<OperationResult<YaraUpdateScheduleConfig>> LoadConfigAsync(CancellationToken ct = default);
    Task<OperationResult<YaraUpdateScheduleConfig>> SaveConfigAsync(YaraUpdateScheduleConfig config, CancellationToken ct = default);
    Task<OperationResult<string>> RunScheduledUpdateNowAsync(CancellationToken ct = default);
    void StartBackgroundLoop();
    void StopBackgroundLoop();
}

public sealed class ScheduledYaraUpdateService : IScheduledYaraUpdateService
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };
    private readonly IYaraEngineService _yara;
    private readonly ISettingsService _settings;
    private readonly SemaphoreSlim _runGate = new(1, 1);
    private CancellationTokenSource? _cts;

    public ScheduledYaraUpdateService(IYaraEngineService yara, ISettingsService settings)
    {
        _yara = yara;
        _settings = settings;
    }

    public YaraUpdateScheduleConfig CurrentConfig { get; private set; } = new();
    public bool IsBackgroundLoopRunning => _cts is not null && !_cts.IsCancellationRequested;
    public event EventHandler<string>? UpdateCompleted;

    private string ConfigPath => Path.Combine(_settings.DataDirectory, "yara", "update-schedule.json");

    public async Task<OperationResult<YaraUpdateScheduleConfig>> LoadConfigAsync(CancellationToken ct = default)
    {
        try
        {
            if (File.Exists(ConfigPath))
            {
                var json = await File.ReadAllTextAsync(ConfigPath, ct).ConfigureAwait(false);
                var loaded = JsonSerializer.Deserialize<YaraUpdateScheduleConfig>(json);
                if (loaded is not null)
                    CurrentConfig = loaded;
            }
            return OperationResult<YaraUpdateScheduleConfig>.Ok(CurrentConfig, "Loaded YARA update schedule.");
        }
        catch (Exception ex)
        {
            return OperationResult<YaraUpdateScheduleConfig>.Fail($"Could not load YARA update schedule: {ex.Message}", "LOAD_ERROR");
        }
    }

    public async Task<OperationResult<YaraUpdateScheduleConfig>> SaveConfigAsync(YaraUpdateScheduleConfig config, CancellationToken ct = default)
    {
        try
        {
            config.IntervalHours = Math.Clamp(config.IntervalHours, 1, 720);
            if (config.RepositoryIds.Count == 0)
                config.RepositoryIds.Add("neo23x0-signature-base");

            CurrentConfig = config;
            var dir = Path.GetDirectoryName(ConfigPath);
            if (!string.IsNullOrWhiteSpace(dir))
                Directory.CreateDirectory(dir);

            var json = JsonSerializer.Serialize(config, JsonOptions);
            await File.WriteAllTextAsync(ConfigPath, json, ct).ConfigureAwait(false);

            if (config.Enabled)
                StartBackgroundLoop();
            else
                StopBackgroundLoop();

            return OperationResult<YaraUpdateScheduleConfig>.Ok(CurrentConfig, "YARA auto-update schedule saved.");
        }
        catch (Exception ex)
        {
            return OperationResult<YaraUpdateScheduleConfig>.Fail($"Failed to save schedule: {ex.Message}", "SAVE_ERROR");
        }
    }

    public bool IsUpdateDue(DateTimeOffset? now = null)
    {
        if (!CurrentConfig.Enabled)
            return false;
        var current = now ?? DateTimeOffset.UtcNow;
        if (CurrentConfig.LastCheckedAt is null)
            return true;
        return (current - CurrentConfig.LastCheckedAt.Value) >= TimeSpan.FromHours(Math.Max(1, CurrentConfig.IntervalHours));
    }

    public async Task<OperationResult<string>> RunScheduledUpdateNowAsync(CancellationToken ct = default)
    {
        await _runGate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            int imported = 0;
            int rejected = 0;
            var errors = new List<string>();

            var repoIds = CurrentConfig.RepositoryIds.Count > 0
                ? CurrentConfig.RepositoryIds
                : new List<string> { "neo23x0-signature-base" };

            foreach (var repoId in repoIds)
            {
                var res = await _yara.UpdateRulesFromRepositoryAsync(repoId, ct).ConfigureAwait(false);
                if (res.Success && res.Value is not null)
                {
                    imported += res.Value.ValidatedAndImportedCount;
                    rejected += res.Value.RejectedCount;
                }
                else
                {
                    errors.Add($"{repoId}: {res.Message}");
                }
            }

            CurrentConfig.LastCheckedAt = DateTimeOffset.UtcNow;
            string summary;
            if (errors.Count == 0)
            {
                CurrentConfig.LastSuccessAt = DateTimeOffset.UtcNow;
                summary = $"Updated {imported} validated rule file(s) ({rejected} incompatible rejected).";
            }
            else
            {
                summary = $"Imported {imported} rule file(s); warnings: {string.Join("; ", errors)}";
            }
            CurrentConfig.LastStatus = summary;
            await SaveConfigAsync(CurrentConfig, ct).ConfigureAwait(false);

            UpdateCompleted?.Invoke(this, summary);
            return errors.Count == 0
                ? OperationResult<string>.Ok(summary, summary)
                : OperationResult<string>.Fail(summary, "PARTIAL_UPDATE");
        }
        finally
        {
            _runGate.Release();
        }
    }

    public void StartBackgroundLoop()
    {
        if (_cts is not null && !_cts.IsCancellationRequested)
            return;

        _cts = new CancellationTokenSource();
        var token = _cts.Token;
        _ = Task.Run(async () =>
        {
            using var timer = new PeriodicTimer(TimeSpan.FromMinutes(15));
            try
            {
                if (IsUpdateDue())
                    await RunScheduledUpdateNowAsync(token).ConfigureAwait(false);

                while (await timer.WaitForNextTickAsync(token).ConfigureAwait(false))
                {
                    if (IsUpdateDue())
                        await RunScheduledUpdateNowAsync(token).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException)
            {
                // Graceful stop
            }
        }, token);
    }

    public void StopBackgroundLoop()
    {
        if (_cts is not null)
        {
            try { _cts.Cancel(); } catch { }
            _cts.Dispose();
            _cts = null;
        }
    }

    public void Dispose()
    {
        StopBackgroundLoop();
        _runGate.Dispose();
    }
}
