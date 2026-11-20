using System.Text.Json;
using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

/// <summary>Append-only JSONL event log under %LocalAppData%\BecettiSecurity\history.jsonl.</summary>
public sealed class EventLogService : IEventLogService
{
    private readonly string _filePath;
    private readonly SemaphoreSlim _gate = new(1, 1);

    public EventLogService(string? dataDirectory = null)
    {
        var dir = dataDirectory ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "BecettiSecurity");
        _filePath = Path.Combine(dir, "history.jsonl");
    }

    public async Task RecordAsync(string type, string summary, bool success, string? detail = null, CancellationToken ct = default)
    {
        var securityEvent = new SecurityEvent
        {
            Timestamp = DateTimeOffset.UtcNow,
            Type = type,
            Summary = summary,
            Detail = detail,
            Success = success
        };

        var line = JsonSerializer.Serialize(securityEvent);

        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_filePath)!);
            await File.AppendAllTextAsync(_filePath, line + Environment.NewLine, ct).ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<IReadOnlyList<SecurityEvent>> ReadRecentAsync(int count = 200, CancellationToken ct = default)
    {
        var events = new List<SecurityEvent>();
        if (!File.Exists(_filePath))
            return events;

        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var lines = await File.ReadAllLinesAsync(_filePath, ct).ConfigureAwait(false);
            foreach (var line in lines)
            {
                if (string.IsNullOrWhiteSpace(line))
                    continue;
                try
                {
                    var parsed = JsonSerializer.Deserialize<SecurityEvent>(line);
                    if (parsed is not null)
                        events.Add(parsed);
                }
                catch
                {
                    // Skip corrupt lines; never fail the whole history view.
                }
            }
        }
        finally
        {
            _gate.Release();
        }

        events.Reverse();
        return events.Take(count).ToList();
    }
}
