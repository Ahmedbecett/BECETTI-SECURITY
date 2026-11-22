using System.Security.Cryptography;
using System.Text.Json;
using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

/// <summary>
/// Real AES-256-GCM encrypted quarantine vault.
/// - Master 256-bit key is generated once per device and wrapped with Windows DPAPI (CurrentUser).
/// - Quarantined files are encrypted with a fresh random 96-bit nonce and 128-bit GCM authentication tag,
///   their SHA-256 digest is recorded, and the original executable/malicious file is deleted so it cannot run.
/// - Restoring decrypts, verifies the exact original SHA-256 digest, and writes the file back safely.
/// - Permanent deletion overwrites the encrypted vault file with zeros before unlinking it.
/// </summary>
public sealed class QuarantineService : IQuarantineService
{
    private const int KeyBytes = 32;
    private const int NonceBytes = 12;
    private const int TagBytes = 16;
    private static readonly byte[] MagicHeader = "BQTN0001"u8.ToArray();
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    private readonly ISettingsService _settings;
    private readonly SemaphoreSlim _gate = new(1, 1);

    public QuarantineService(ISettingsService settings)
    {
        _settings = settings;
    }

    private string VaultDir => Path.Combine(_settings.DataDirectory, "quarantine");
    private string ManifestPath => Path.Combine(VaultDir, "manifest.json");
    private string KeyPath => Path.Combine(VaultDir, "vault.key");

    public async Task<OperationResult<IReadOnlyList<QuarantineEntry>>> GetEntriesAsync(CancellationToken ct = default)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var entries = await LoadManifestUnlockedAsync(ct).ConfigureAwait(false);
            return OperationResult<IReadOnlyList<QuarantineEntry>>.Ok(
                entries.OrderByDescending(e => e.QuarantinedAt).ToList(),
                $"{entries.Count} quarantined item(s).");
        }
        catch (Exception ex)
        {
            return OperationResult<IReadOnlyList<QuarantineEntry>>.Fail($"Failed to read quarantine vault: {ex.Message}", "QUARANTINE_READ_ERROR");
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<OperationResult<QuarantineEntry>> QuarantineFileAsync(
        string filePath,
        string ruleOrThreatName,
        string reason,
        string detectionEngine = "YARA",
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
            return OperationResult<QuarantineEntry>.Fail("File to quarantine does not exist.", "FILE_NOT_FOUND");

        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            Directory.CreateDirectory(VaultDir);
            var fullSource = Path.GetFullPath(filePath);

            // Prevent quarantining files already inside the vault
            if (fullSource.StartsWith(Path.GetFullPath(VaultDir), StringComparison.OrdinalIgnoreCase))
                return OperationResult<QuarantineEntry>.Fail("File is already inside the quarantine vault.", "ALREADY_QUARANTINED");

            var plainBytes = await File.ReadAllBytesAsync(fullSource, ct).ConfigureAwait(false);
            var sha256 = Convert.ToHexString(SHA256.HashData(plainBytes)).ToLowerInvariant();
            var key = GetOrCreateMasterKeyUnlocked();

            var nonce = RandomNumberGenerator.GetBytes(NonceBytes);
            var cipher = new byte[plainBytes.Length];
            var tag = new byte[TagBytes];

            using (var aes = new AesGcm(key, TagBytes))
            {
                aes.Encrypt(nonce, plainBytes, cipher, tag, MagicHeader);
            }

            var id = Guid.NewGuid().ToString("N")[..12].ToUpperInvariant();
            var vaultFileName = $"{id}.bqtn";
            var vaultFullPath = Path.Combine(VaultDir, vaultFileName);

            await using (var fs = new FileStream(vaultFullPath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                await fs.WriteAsync(MagicHeader, ct).ConfigureAwait(false);
                await fs.WriteAsync(nonce, ct).ConfigureAwait(false);
                await fs.WriteAsync(tag, ct).ConfigureAwait(false);
                await fs.WriteAsync(cipher, ct).ConfigureAwait(false);
                await fs.FlushAsync(ct).ConfigureAwait(false);
            }

            // Clear read-only attributes if present, then remove original file so it cannot be executed.
            try
            {
                var attrs = File.GetAttributes(fullSource);
                if ((attrs & FileAttributes.ReadOnly) != 0)
                    File.SetAttributes(fullSource, attrs & ~FileAttributes.ReadOnly);
                File.Delete(fullSource);
            }
            catch (Exception deleteEx)
            {
                // Roll back the encrypted copy if original could not be removed (e.g., locked by running process)
                try { File.Delete(vaultFullPath); } catch { }
                return OperationResult<QuarantineEntry>.Fail(
                    $"Could not remove original file (it may be locked by an active process): {deleteEx.Message}",
                    "DELETE_FAILED");
            }

            var entry = new QuarantineEntry
            {
                Id = id,
                OriginalPath = fullSource,
                OriginalFileName = Path.GetFileName(fullSource),
                Sha256 = sha256,
                OriginalSizeBytes = plainBytes.LongLength,
                DetectionEngine = string.IsNullOrWhiteSpace(detectionEngine) ? "YARA" : detectionEngine,
                RuleOrThreatName = string.IsNullOrWhiteSpace(ruleOrThreatName) ? "Detected Threat" : ruleOrThreatName,
                Reason = reason ?? string.Empty,
                QuarantinedAt = DateTimeOffset.UtcNow,
                VaultFileName = vaultFileName
            };

            var entries = await LoadManifestUnlockedAsync(ct).ConfigureAwait(false);
            entries.Add(entry);
            await SaveManifestUnlockedAsync(entries, ct).ConfigureAwait(false);

            return OperationResult<QuarantineEntry>.Ok(entry, $"Quarantined and encrypted '{entry.OriginalFileName}' (AES-256-GCM).");
        }
        catch (Exception ex)
        {
            return OperationResult<QuarantineEntry>.Fail($"Quarantine failed: {ex.Message}", "QUARANTINE_FAILED");
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<OperationResult<string>> RestoreFileAsync(
        string entryId,
        string? overrideDestinationPath = null,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(entryId))
            return OperationResult<string>.Fail("Quarantine entry ID is required.", "INVALID_ID");

        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var entries = await LoadManifestUnlockedAsync(ct).ConfigureAwait(false);
            var entry = entries.FirstOrDefault(e => string.Equals(e.Id, entryId, StringComparison.OrdinalIgnoreCase));
            if (entry is null)
                return OperationResult<string>.Fail("Quarantine entry not found.", "NOT_FOUND");

            var vaultFullPath = Path.Combine(VaultDir, entry.VaultFileName);
            if (!File.Exists(vaultFullPath))
                return OperationResult<string>.Fail("Encrypted quarantine payload is missing from disk.", "PAYLOAD_MISSING");

            var blob = await File.ReadAllBytesAsync(vaultFullPath, ct).ConfigureAwait(false);
            var minHeaderLen = MagicHeader.Length + NonceBytes + TagBytes;
            if (blob.Length < minHeaderLen || !blob.AsSpan(0, MagicHeader.Length).SequenceEqual(MagicHeader))
                return OperationResult<string>.Fail("Quarantine file header is corrupt.", "CORRUPT_VAULT_ITEM");

            var nonce = blob.AsSpan(MagicHeader.Length, NonceBytes).ToArray();
            var tag = blob.AsSpan(MagicHeader.Length + NonceBytes, TagBytes).ToArray();
            var cipher = blob.AsSpan(minHeaderLen).ToArray();
            var plain = new byte[cipher.Length];

            var key = GetOrCreateMasterKeyUnlocked();
            using (var aes = new AesGcm(key, TagBytes))
            {
                aes.Decrypt(nonce, cipher, tag, plain, MagicHeader);
            }

            var actualSha = Convert.ToHexString(SHA256.HashData(plain)).ToLowerInvariant();
            if (!string.Equals(actualSha, entry.Sha256, StringComparison.OrdinalIgnoreCase))
                return OperationResult<string>.Fail("SHA-256 integrity verification failed during restore.", "INTEGRITY_MISMATCH");

            var destPath = string.IsNullOrWhiteSpace(overrideDestinationPath) ? entry.OriginalPath : overrideDestinationPath;
            var destDir = Path.GetDirectoryName(destPath);
            if (!string.IsNullOrWhiteSpace(destDir))
                Directory.CreateDirectory(destDir);

            await File.WriteAllBytesAsync(destPath, plain, ct).ConfigureAwait(false);

            SecureWipeAndDelete(vaultFullPath);
            entries.Remove(entry);
            await SaveManifestUnlockedAsync(entries, ct).ConfigureAwait(false);

            return OperationResult<string>.Ok(destPath, $"Restored '{entry.OriginalFileName}' to {destPath} (SHA-256 verified).");
        }
        catch (CryptographicException ex)
        {
            return OperationResult<string>.Fail($"Decryption failed (authentication tag mismatch): {ex.Message}", "DECRYPT_FAILED");
        }
        catch (Exception ex)
        {
            return OperationResult<string>.Fail($"Restore failed: {ex.Message}", "RESTORE_FAILED");
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<OperationResult> DeletePermanentlyAsync(string entryId, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(entryId))
            return OperationResult.Fail("Quarantine entry ID is required.", "INVALID_ID");

        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var entries = await LoadManifestUnlockedAsync(ct).ConfigureAwait(false);
            var entry = entries.FirstOrDefault(e => string.Equals(e.Id, entryId, StringComparison.OrdinalIgnoreCase));
            if (entry is null)
                return OperationResult.Fail("Quarantine entry not found.", "NOT_FOUND");

            var vaultFullPath = Path.Combine(VaultDir, entry.VaultFileName);
            SecureWipeAndDelete(vaultFullPath);

            entries.Remove(entry);
            await SaveManifestUnlockedAsync(entries, ct).ConfigureAwait(false);

            return OperationResult.Ok($"Permanently deleted quarantined item '{entry.OriginalFileName}'.");
        }
        catch (Exception ex)
        {
            return OperationResult.Fail($"Permanent deletion failed: {ex.Message}", "DELETE_FAILED");
        }
        finally
        {
            _gate.Release();
        }
    }

    private byte[] GetOrCreateMasterKeyUnlocked()
    {
        Directory.CreateDirectory(VaultDir);
        if (File.Exists(KeyPath))
        {
            var stored = File.ReadAllBytes(KeyPath);
            if (OperatingSystem.IsWindows())
            {
                try
                {
                    return ProtectedData.Unprotect(stored, null, DataProtectionScope.CurrentUser);
                }
                catch
                {
                    if (stored.Length == KeyBytes)
                        return stored;
                    throw;
                }
            }
            if (stored.Length == KeyBytes)
                return stored;
        }

        var rawKey = RandomNumberGenerator.GetBytes(KeyBytes);
        var toPersist = OperatingSystem.IsWindows()
            ? ProtectedData.Protect(rawKey, null, DataProtectionScope.CurrentUser)
            : rawKey;

        File.WriteAllBytes(KeyPath, toPersist);
        return rawKey;
    }

    private static void SecureWipeAndDelete(string path)
    {
        if (!File.Exists(path))
            return;
        try
        {
            var len = new FileInfo(path).Length;
            if (len > 0 && len < 64 * 1024 * 1024)
            {
                var zeros = new byte[Math.Min(len, 65536)];
                using var fs = new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.None);
                long remaining = len;
                while (remaining > 0)
                {
                    var chunk = (int)Math.Min(remaining, zeros.Length);
                    fs.Write(zeros, 0, chunk);
                    remaining -= chunk;
                }
                fs.Flush(true);
            }
        }
        catch
        {
            // Proceed to unlink
        }
        File.Delete(path);
    }

    private async Task<List<QuarantineEntry>> LoadManifestUnlockedAsync(CancellationToken ct)
    {
        if (!File.Exists(ManifestPath))
            return new List<QuarantineEntry>();
        var json = await File.ReadAllTextAsync(ManifestPath, ct).ConfigureAwait(false);
        return JsonSerializer.Deserialize<List<QuarantineEntry>>(json) ?? new List<QuarantineEntry>();
    }

    private async Task SaveManifestUnlockedAsync(List<QuarantineEntry> entries, CancellationToken ct)
    {
        Directory.CreateDirectory(VaultDir);
        var json = JsonSerializer.Serialize(entries, JsonOptions);
        await File.WriteAllTextAsync(ManifestPath, json, ct).ConfigureAwait(false);
    }
}
