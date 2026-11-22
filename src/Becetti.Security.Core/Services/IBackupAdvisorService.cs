using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

/// <summary>
/// Backup Advisor: reports the real backup posture Windows itself already
/// has configured — File History's service state and System Restore's real
/// shadow copies (Win32_ShadowCopy, the same data vssadmin reads). BECETTI
/// SECURITY implements no backup engine of its own.
/// </summary>
public interface IBackupAdvisorService
{
    Task<OperationResult<BackupStatus>> GetStatusAsync(CancellationToken ct = default);
}
