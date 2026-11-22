using System.Security.Cryptography;
using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

/// <summary>
/// Real secure-delete implementation: for each pass, the file is opened,
/// its actual length is read, and that many cryptographically-random bytes
/// are written over its content and flushed to disk, before the file is
/// finally deleted. On an SSD with wear-leveling this does not guarantee
/// the original bytes are unrecoverable at the hardware level — no
/// software tool honestly can — but it does overwrite every byte the
/// filesystem itself reports for this file, which is what this feature
/// claims and nothing more.
/// </summary>
public sealed class FileShredderService : IFileShredderService
{
    public async Task<OperationResult> ShredFileAsync(string path, int passes = 3, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(path))
            return OperationResult.Fail("No file path given.", "BAD_REQUEST");

        if (!File.Exists(path))
            return OperationResult.Fail("File not found.", "FILE_NOT_FOUND");

        if (passes < 1)
            passes = 1;

        try
        {
            var length = new FileInfo(path).Length;

            if (length > 0)
            {
                var buffer = new byte[Math.Min(length, 1024 * 1024)]; // 1 MB chunks

                for (var pass = 0; pass < passes; pass++)
                {
                    ct.ThrowIfCancellationRequested();

                    using var stream = new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.None);
                    long written = 0;
                    while (written < length)
                    {
                        var chunkSize = (int)Math.Min(buffer.Length, length - written);
                        RandomNumberGenerator.Fill(buffer.AsSpan(0, chunkSize));
                        await stream.WriteAsync(buffer.AsMemory(0, chunkSize), ct).ConfigureAwait(false);
                        written += chunkSize;
                    }
                    await stream.FlushAsync(ct).ConfigureAwait(false);
                }
            }

            File.Delete(path);
            return OperationResult.Ok($"Overwrote and deleted the file ({passes} pass{(passes == 1 ? "" : "es")}).");
        }
        catch (UnauthorizedAccessException ex)
        {
            return OperationResult.Fail($"Access denied: {ex.Message}", "ACCESS_DENIED");
        }
        catch (IOException ex)
        {
            return OperationResult.Fail($"The file could not be shredded (it may be open elsewhere): {ex.Message}", "IO_ERROR");
        }
        catch (Exception ex)
        {
            return OperationResult.Fail($"Shredding failed: {ex.Message}", "ERROR");
        }
    }
}
