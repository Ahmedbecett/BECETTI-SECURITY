using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

/// <summary>
/// Local AES-256-GCM encrypted quarantine vault for isolating malicious files
/// detected by the Native YARA Engine or other local guards.
/// </summary>
public interface IQuarantineService
{
    Task<OperationResult<IReadOnlyList<QuarantineEntry>>> GetEntriesAsync(CancellationToken ct = default);
    Task<OperationResult<QuarantineEntry>> QuarantineFileAsync(
        string filePath,
        string ruleOrThreatName,
        string reason,
        string detectionEngine = "YARA",
        CancellationToken ct = default);
    Task<OperationResult<string>> RestoreFileAsync(string entryId, string? overrideDestinationPath = null, CancellationToken ct = default);
    Task<OperationResult> DeletePermanentlyAsync(string entryId, CancellationToken ct = default);
}
