using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

/// <summary>
/// Real static file forensics analyzer: SHA-256, Shannon entropy, PE32/PE32+ header &amp; section
/// inspection, suspicious API detection, and Windows Authenticode digital signature verification.
/// </summary>
public interface IFileForensicsService
{
    Task<OperationResult<FileForensicsReport>> AnalyzeFileAsync(string filePath, CancellationToken ct = default);
    AuthenticodeInfo VerifyAuthenticode(string filePath);
}
