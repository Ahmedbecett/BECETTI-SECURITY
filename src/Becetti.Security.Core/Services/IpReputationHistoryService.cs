using System.Text.Json;
using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

/// <summary>
/// Append-only JSONL store under %LocalAppData%\BecettiSecurity\ipreputation-history.jsonl.
/// Mirrors DataBreachHistoryService/ThreatIntelHistoryService's storage pattern.
/// </summary>
public sealed class IpReputationHistoryService : IIpReputationHistoryService
{
    private readonly string _filePath;
    private readonly SemaphoreSlim _gate = new(1, 1);

    public IpReputationHistoryService(string? dataDirectory = null)
    {
        var dir = dataDirectory ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "BecettiSecurity");
        _filePath = Path.Combine(dir, "ipreputation-history.jsonl");
    }

    public async Task RecordAsync(IpReputationCheckRecord record, CancellationToken ct = default)
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

    public async Task<IReadOnlyList<IpReputationCheckRecord>> ReadRecentAsync(int count = 100, CancellationToken ct = default)
    {
        var records = new List<IpReputationCheckRecord>();
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
                    var parsed = JsonSerializer.Deserialize<IpReputationCheckRecord>(line);
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
