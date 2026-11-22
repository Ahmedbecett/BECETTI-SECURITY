using System.Diagnostics;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

public interface IIncidentEvidenceService
{
    Task<OperationResult<IncidentBundleResult>> ExportForensicBundleAsync(string? outputDirectory = null, CancellationToken ct = default);
}

/// <summary>
/// 1-Click Forensic Incident Evidence Bundle Exporter (.zip):
/// collects real live system telemetry (processes, network connections, YARA status,
/// deep persistence audit, Windows hardening posture, hosts/DNS, camera/mic access,
/// quarantine manifest, and recent security events) into a timestamped ZIP with SHA-256 verification.
/// </summary>
public sealed class IncidentEvidenceService : IIncidentEvidenceService
{
    private readonly IYaraEngineService _yara;
    private readonly INetworkMonitorService _network;
    private readonly IPersistenceHunterService _persistence;
    private readonly IHostsDnsGuardService _hosts;
    private readonly ICameraMicAuditorService _cameraMic;
    private readonly IWindowsHardeningService _hardening;
    private readonly IQuarantineService _quarantine;
    private readonly IEventLogService _events;

    private static readonly JsonSerializerOptions PrettyJson = new() { WriteIndented = true };

    public IncidentEvidenceService(
        IYaraEngineService yara,
        INetworkMonitorService network,
        IPersistenceHunterService persistence,
        IHostsDnsGuardService hosts,
        ICameraMicAuditorService cameraMic,
        IWindowsHardeningService hardening,
        IQuarantineService quarantine,
        IEventLogService events)
    {
        _yara = yara;
        _network = network;
        _persistence = persistence;
        _hosts = hosts;
        _cameraMic = cameraMic;
        _hardening = hardening;
        _quarantine = quarantine;
        _events = events;
    }

    public async Task<OperationResult<IncidentBundleResult>> ExportForensicBundleAsync(
        string? outputDirectory = null,
        CancellationToken ct = default)
    {
        try
        {
            var outDir = string.IsNullOrWhiteSpace(outputDirectory)
                ? Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
                    "BECETTI-Forensic-Evidence")
                : outputDirectory;

            Directory.CreateDirectory(outDir);

            var stamp = DateTimeOffset.UtcNow.ToString("yyyyMMdd-HHmmss");
            var zipPath = Path.Combine(outDir, $"BECETTI-Incident-Bundle-{stamp}.zip");
            var artifacts = new List<string>();

            // Collect real artifacts concurrently where safe
            var yaraTask = SafeAsync(() => _yara.InitializeAsync(ct));
            var netTask = SafeAsync(() => _network.GetActiveConnectionsAsync(ct));
            var persistTask = SafeAsync(() => _persistence.AuditAsync(ct));
            var hostsTask = SafeAsync(() => _hosts.AuditAsync(ct));
            var camTask = SafeAsync(() => _cameraMic.AuditAsync(ct));
            var hardenTask = SafeAsync(() => _hardening.AuditAsync(ct));
            var quarTask = SafeAsync(() => _quarantine.GetEntriesAsync(ct));
            var eventsTask = SafeAsync(() => _events.ReadRecentAsync(200, ct));

            await Task.WhenAll(yaraTask, netTask, persistTask, hostsTask, camTask, hardenTask, quarTask, eventsTask)
                .ConfigureAwait(false);

            var runningProcesses = CaptureRunningProcesses();

            using (var fs = new FileStream(zipPath, FileMode.Create, FileAccess.ReadWrite, FileShare.None))
            using (var zip = new ZipArchive(fs, ZipArchiveMode.Create, leaveOpen: false))
            {
                AddJsonEntry(zip, "processes.json", runningProcesses, artifacts);
                AddJsonEntry(zip, "yara-engine.json", yaraTask.Result, artifacts);
                AddJsonEntry(zip, "network-connections.json", netTask.Result, artifacts);
                AddJsonEntry(zip, "persistence-audit.json", persistTask.Result, artifacts);
                AddJsonEntry(zip, "hosts-dns.json", hostsTask.Result, artifacts);
                AddJsonEntry(zip, "camera-mic-access.json", camTask.Result, artifacts);
                AddJsonEntry(zip, "windows-hardening.json", hardenTask.Result, artifacts);
                AddJsonEntry(zip, "quarantine-manifest.json", quarTask.Result, artifacts);
                AddJsonEntry(zip, "security-events.json", eventsTask.Result, artifacts);

                var summary = new StringBuilder();
                summary.AppendLine("BECETTI SECURITY — FORENSIC INCIDENT EVIDENCE BUNDLE");
                summary.AppendLine($"Generated (UTC): {DateTimeOffset.UtcNow:O}");
                summary.AppendLine($"Machine:         {Environment.MachineName}");
                summary.AppendLine($"User:            {Environment.UserName}");
                summary.AppendLine($"OS:              {Environment.OSVersion}");
                summary.AppendLine($"Processes:       {runningProcesses.Count}");
                summary.AppendLine($"Included files:  {string.Join(", ", artifacts)}");
                AddTextEntry(zip, "SUMMARY.txt", summary.ToString(), artifacts);
            }

            var fi = new FileInfo(zipPath);
            string sha256;
            await using (var rf = File.OpenRead(zipPath))
            {
                sha256 = Convert.ToHexString(await SHA256.HashDataAsync(rf, ct).ConfigureAwait(false));
            }

            var result = new IncidentBundleResult
            {
                BundleZipPath = zipPath,
                SizeBytes = fi.Length,
                Sha256 = sha256,
                GeneratedAt = DateTimeOffset.UtcNow,
                IncludedArtifacts = artifacts
            };

            return OperationResult<IncidentBundleResult>.Ok(
                result,
                $"Exported forensic bundle ({artifacts.Count} artifacts, {fi.Length / 1024.0:F1} KB) to {zipPath}");
        }
        catch (Exception ex)
        {
            return OperationResult<IncidentBundleResult>.Fail($"Failed to export forensic evidence bundle: {ex.Message}", "BUNDLE_ERROR");
        }
    }

    private static List<object> CaptureRunningProcesses()
    {
        var list = new List<object>();
        foreach (var p in Process.GetProcesses())
        {
            try
            {
                string? path = null;
                try { path = p.MainModule?.FileName; } catch { }
                list.Add(new
                {
                    p.Id,
                    p.ProcessName,
                    ExecutablePath = path,
                    WorkingSetMb = Math.Round(p.WorkingSet64 / (1024.0 * 1024.0), 2)
                });
            }
            catch { }
            finally { p.Dispose(); }
        }
        return list;
    }

    private static void AddJsonEntry(ZipArchive zip, string name, object? payload, List<string> artifacts)
    {
        var json = JsonSerializer.Serialize(payload ?? new { status = "unavailable" }, PrettyJson);
        AddTextEntry(zip, name, json, artifacts);
    }

    private static void AddTextEntry(ZipArchive zip, string name, string content, List<string> artifacts)
    {
        var entry = zip.CreateEntry(name, CompressionLevel.Optimal);
        using var writer = new StreamWriter(entry.Open(), Encoding.UTF8);
        writer.Write(content);
        artifacts.Add(name);
    }

    private static async Task<object?> SafeAsync<T>(Func<Task<T>> action)
    {
        try { return await action().ConfigureAwait(false); }
        catch (Exception ex) { return new { error = ex.Message }; }
    }
}
