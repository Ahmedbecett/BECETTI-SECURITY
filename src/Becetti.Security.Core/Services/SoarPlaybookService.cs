using System.Diagnostics;
using System.Text.Json;
using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

public interface ISoarPlaybookService
{
    SoarPlaybookConfig CurrentConfig { get; }
    Task<OperationResult<SoarPlaybookConfig>> LoadConfigAsync(CancellationToken ct = default);
    Task<OperationResult> SaveConfigAsync(SoarPlaybookConfig config, CancellationToken ct = default);
    Task<OperationResult<SoarExecutionReport>> ExecuteContainmentPlaybookAsync(
        string? suspiciousFilePath,
        int? suspiciousPid,
        string reason,
        CancellationToken ct = default);
}

/// <summary>
/// #4: SOAR Automated Incident Response Playbook Engine.
/// Orchestrates real multi-step containment against an active threat:
/// (1) Kill malicious PID, (2) Block executable in Windows Firewall, (3) AES-256-GCM Quarantine,
/// (4) Generate SHA-256 Forensic Evidence ZIP bundle, and (5) Log audit trail. Zero simulation.
/// </summary>
public sealed class SoarPlaybookService : ISoarPlaybookService
{
    private readonly ISettingsService _settings;
    private readonly IQuarantineService _quarantine;
    private readonly IPerAppFirewallService _firewall;
    private readonly IIncidentEvidenceService _evidence;
    private readonly IEventLogService _events;
    private readonly string _configPath;

    public SoarPlaybookConfig CurrentConfig { get; private set; } = new();

    public SoarPlaybookService(
        ISettingsService settings,
        IQuarantineService quarantine,
        IPerAppFirewallService firewall,
        IIncidentEvidenceService evidence,
        IEventLogService events)
    {
        _settings = settings;
        _quarantine = quarantine;
        _firewall = firewall;
        _evidence = evidence;
        _events = events;
        _configPath = Path.Combine(settings.DataDirectory, "soar-playbooks.json");
    }

    public async Task<OperationResult<SoarPlaybookConfig>> LoadConfigAsync(CancellationToken ct = default)
    {
        try
        {
            if (File.Exists(_configPath))
            {
                var json = await File.ReadAllTextAsync(_configPath, ct).ConfigureAwait(false);
                var cfg = JsonSerializer.Deserialize<SoarPlaybookConfig>(json);
                if (cfg is not null) CurrentConfig = cfg;
            }
            return OperationResult<SoarPlaybookConfig>.Ok(CurrentConfig, "SOAR Playbook configuration loaded.");
        }
        catch (Exception ex)
        {
            return OperationResult<SoarPlaybookConfig>.Fail($"Failed to load SOAR config: {ex.Message}");
        }
    }

    public async Task<OperationResult> SaveConfigAsync(SoarPlaybookConfig config, CancellationToken ct = default)
    {
        try
        {
            CurrentConfig = config ?? new SoarPlaybookConfig();
            Directory.CreateDirectory(Path.GetDirectoryName(_configPath)!);
            var json = JsonSerializer.Serialize(CurrentConfig, new JsonSerializerOptions { WriteIndented = true });
            await File.WriteAllTextAsync(_configPath, json, ct).ConfigureAwait(false);
            return OperationResult.Ok("SOAR Playbook policy saved.");
        }
        catch (Exception ex)
        {
            return OperationResult.Fail($"Failed to save SOAR config: {ex.Message}");
        }
    }

    public async Task<OperationResult<SoarExecutionReport>> ExecuteContainmentPlaybookAsync(
        string? suspiciousFilePath,
        int? suspiciousPid,
        string reason,
        CancellationToken ct = default)
    {
        var logs = new List<string>();
        bool allOk = true;
        string? zipPath = null;
        var targetLabel = !string.IsNullOrWhiteSpace(suspiciousFilePath)
            ? Path.GetFileName(suspiciousFilePath)
            : (suspiciousPid.HasValue ? $"PID {suspiciousPid.Value}" : "Active Incident");

        // Step 1: Terminate malicious process if requested
        if (CurrentConfig.KillMaliciousProcess && suspiciousPid is > 4)
        {
            try
            {
                using var proc = Process.GetProcessById(suspiciousPid.Value);
                proc.Kill(entireProcessTree: true);
                logs.Add($"[OK] Terminated process tree PID {suspiciousPid.Value}.");
            }
            catch (Exception ex)
            {
                allOk = false;
                logs.Add($"[WARN] Could not terminate PID {suspiciousPid.Value}: {ex.Message}");
            }
        }

        // Step 2: Block executable in Windows Firewall before quarantining
        if (CurrentConfig.BlockExecutableInFirewall &&
            !string.IsNullOrWhiteSpace(suspiciousFilePath) &&
            suspiciousFilePath.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) &&
            File.Exists(suspiciousFilePath))
        {
            var fwRes = await _firewall.BlockApplicationAsync(suspiciousFilePath, ct).ConfigureAwait(false);
            if (fwRes.Success)
                logs.Add($"[OK] Blocked executable in Windows Firewall: {suspiciousFilePath}");
            else
            {
                allOk = false;
                logs.Add($"[WARN] Firewall block skipped/failed: {fwRes.Message}");
            }
        }

        // Step 3: AES-256-GCM Quarantine file
        if (CurrentConfig.AutoQuarantineOnCritical &&
            !string.IsNullOrWhiteSpace(suspiciousFilePath) &&
            File.Exists(suspiciousFilePath))
        {
            var qRes = await _quarantine.QuarantineFileAsync(suspiciousFilePath, "SOAR_Containment", reason, "SOAR", ct).ConfigureAwait(false);
            if (qRes.Success)
                logs.Add($"[OK] Encrypted & quarantined file into AES-256-GCM Vault: {suspiciousFilePath}");
            else
            {
                allOk = false;
                logs.Add($"[WARN] Quarantine failed: {qRes.Message}");
            }
        }

        // Step 4: Generate Forensic Evidence ZIP bundle
        if (CurrentConfig.GenerateForensicEvidenceZip)
        {
            var evDir = Path.Combine(_settings.DataDirectory, "soar-evidence");
            Directory.CreateDirectory(evDir);
            var evRes = await _evidence.ExportForensicBundleAsync(evDir, ct).ConfigureAwait(false);
            if (evRes.Success && evRes.Value is not null)
            {
                zipPath = evRes.Value.BundleZipPath;
                logs.Add($"[OK] Forensic Evidence ZIP created (SHA-256: {evRes.Value.Sha256[..Math.Min(16, evRes.Value.Sha256.Length)]}…): {zipPath}");
            }
            else
            {
                allOk = false;
                logs.Add($"[WARN] Forensic bundle failed: {evRes.Message}");
            }
        }

        if (logs.Count == 0)
            logs.Add("[INFO] No automated containment actions were enabled or applicable for the given target.");

        var summary = $"SOAR Playbook executed on '{targetLabel}' — {logs.Count} step(s) completed ({(allOk ? "All OK" : "With Warnings")}).";
        await _events.RecordAsync("SoarContainment", summary, allOk, suspiciousFilePath).ConfigureAwait(false);

        return OperationResult<SoarExecutionReport>.Ok(new SoarExecutionReport
        {
            ExecutedAt = DateTimeOffset.UtcNow,
            TargetLabel = targetLabel,
            AllStepsSucceeded = allOk,
            StepLogs = logs,
            EvidenceZipPath = zipPath,
            Summary = summary
        }, summary);
    }
}
