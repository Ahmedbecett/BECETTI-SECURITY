using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

/// <summary>
/// Securely deletes a file by overwriting its real content on disk before
/// removing it, rather than a normal delete (which only unlinks the file —
/// the bytes typically remain recoverable until overwritten by something
/// else). Every pass genuinely writes random bytes to the file's real size
/// and flushes to disk; nothing here is simulated.
/// </summary>
public interface IFileShredderService
{
    /// <summary>Overwrites the file's content this many times with random bytes before deleting it. Default 3.</summary>
    Task<OperationResult> ShredFileAsync(string path, int passes = 3, CancellationToken ct = default);
}
