using System.Security.Cryptography;
using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

public interface ISecureShredderService
{
    Task<OperationResult<FileShredReport>> ShredFileAsync(string filePath, int passes = 3, CancellationToken ct = default);
}

/// <summary>
/// Real Secure File Shredder (DoD 5220.22-M 3-pass or 7-pass):
/// overwrites every byte of a file directly on disk (zeroes, ones, and CSPRNG random bytes)
/// with Flush(flushToDisk: true), truncates to 0 bytes, renames to a randomized name to scrub
/// directory entry metadata, and unlinks permanently. Blocks protected OS system directories.
/// </summary>
public sealed class SecureShredderService : ISecureShredderService
{
    public async Task<OperationResult<FileShredReport>> ShredFileAsync(string filePath, int passes = 3, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(filePath))
            return OperationResult<FileShredReport>.Fail("Select a file path to shred.", "EMPTY_PATH");

        var fullPath = Path.GetFullPath(filePath.Trim());
        if (!File.Exists(fullPath))
            return OperationResult<FileShredReport>.Fail($"File not found: {fullPath}", "NOT_FOUND");

        // Safety guard: never allow shredding inside Windows or Program Files system directories
        var winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var progFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var progFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);

        if ((!string.IsNullOrEmpty(winDir) && fullPath.StartsWith(winDir, StringComparison.OrdinalIgnoreCase)) ||
            (!string.IsNullOrEmpty(progFiles) && fullPath.StartsWith(progFiles, StringComparison.OrdinalIgnoreCase)) ||
            (!string.IsNullOrEmpty(progFilesX86) && fullPath.StartsWith(progFilesX86, StringComparison.OrdinalIgnoreCase)))
        {
            return OperationResult<FileShredReport>.Fail("Refusing to shred protected OS/Program Files path for system safety.", "PROTECTED_PATH");
        }

        int actualPasses = passes >= 7 ? 7 : 3;
        string standard = actualPasses == 7 ? "DoD 5220.22-M ECE (7-Pass)" : "DoD 5220.22-M (3-Pass)";

        try
        {
            // Clear ReadOnly attribute if set
            var attrs = File.GetAttributes(fullPath);
            if ((attrs & FileAttributes.ReadOnly) != 0)
                File.SetAttributes(fullPath, attrs & ~FileAttributes.ReadOnly);

            long fileLength = new FileInfo(fullPath).Length;
            long totalWritten = 0;

            await Task.Run(() =>
            {
                const int bufferSize = 64 * 1024;
                var buffer = new byte[bufferSize];

                using (var fs = new FileStream(fullPath, FileMode.Open, FileAccess.Write, FileShare.None, bufferSize, FileOptions.WriteThrough))
                {
                    for (int pass = 0; pass < actualPasses; pass++)
                    {
                        ct.ThrowIfCancellationRequested();
                        fs.Position = 0;
                        long remaining = fileLength;

                        // DoD pattern: pass 0 = 0x00, pass 1 = 0xFF, pass 2 = CSPRNG random (repeated for 7-pass)
                        int patternType = pass % 3;
                        if (patternType == 0) Array.Fill(buffer, (byte)0x00);
                        else if (patternType == 1) Array.Fill(buffer, (byte)0xFF);

                        while (remaining > 0)
                        {
                            ct.ThrowIfCancellationRequested();
                            int chunk = (int)Math.Min(bufferSize, remaining);
                            if (patternType == 2)
                                RandomNumberGenerator.Fill(buffer.AsSpan(0, chunk));

                            fs.Write(buffer, 0, chunk);
                            remaining -= chunk;
                            totalWritten += chunk;
                        }

                        fs.Flush(flushToDisk: true);
                    }

                    fs.SetLength(0);
                    fs.Flush(flushToDisk: true);
                }

                // Scrub filename metadata via random rename before final delete
                var dir = Path.GetDirectoryName(fullPath)!;
                var randomName = Path.Combine(dir, $"_{Guid.NewGuid():N}.tmp");
                string pathToDelete = fullPath;
                try
                {
                    File.Move(fullPath, randomName);
                    pathToDelete = randomName;
                }
                catch { }

                File.Delete(pathToDelete);
            }, ct).ConfigureAwait(false);

            var report = new FileShredReport
            {
                OriginalPath = fullPath,
                BytesOverwritten = totalWritten,
                PassesCompleted = actualPasses,
                Standard = standard,
                ShreddedAt = DateTimeOffset.UtcNow
            };

            return OperationResult<FileShredReport>.Ok(
                report,
                $"Permanently shredded '{Path.GetFileName(fullPath)}' ({actualPasses} passes, {totalWritten:N0} bytes overwritten).");
        }
        catch (OperationCanceledException)
        {
            return OperationResult<FileShredReport>.Fail("Shred operation was canceled.", "CANCELED");
        }
        catch (Exception ex)
        {
            return OperationResult<FileShredReport>.Fail($"Secure shred failed: {ex.Message}", "SHRED_ERROR");
        }
    }
}
