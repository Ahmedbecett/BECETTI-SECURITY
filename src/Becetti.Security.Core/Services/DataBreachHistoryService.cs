using System.Text.Json;
using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

/// <summary>
/// Append-only JSONL store under %LocalAppData%\BecettiSecurity\databreach-history.jsonl.
/// Mirrors ThreatIntelHistoryService's storage pattern, kept as its own file
/// because data-breach checks are a distinct feature with their own
/// feature-specific fields (check type, breach/times-seen count).
/// </summary>
public sealed class DataBreachHistoryService : IDataBreachHistoryService
{
    private readonly string _filePath;
    private readonly SemaphoreSlim _gate = new(1, 1);

    public DataBreachHistoryService(string? dataDirectory = null)
    {
        var dir = dataDirectory ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "BecettiSecurity");
        _filePath = Path.Combine(dir, "databreach-history.jsonl");
    }

    public async Task RecordAsync(DataBreachCheckRecord record, CancellationToken ct = default)
    {
        var line = JsonSerializer.Serialize(record);

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

    public async Task<IReadOnlyList<DataBreachCheckRecord>> ReadRecentAsync(int count = 100, CancellationToken ct = default)
    {
        var records = new List<DataBreachCheckRecord>();
        if (!File.Exists(_filePath))
            return records;

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
                    var parsed = JsonSerializer.Deserialize<DataBreachCheckRecord>(line);
                    if (parsed is not null)
                        records.Add(parsed);
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

        records.Reverse();
        return records.Take(count).ToList();
    }
}
