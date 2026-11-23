using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

public interface IVaultProService
{
    Task<OperationResult<IReadOnlyList<VaultProItem>>> ListItemsAsync(CancellationToken ct = default);
    Task<OperationResult<VaultProItem>> SealFileOrFolderAsync(string sourcePath, string passphrase, CancellationToken ct = default);
    Task<OperationResult<string>> UnsealItemAsync(string itemId, string passphrase, string destinationFolder, CancellationToken ct = default);
    Task<OperationResult> DeleteItemAsync(string itemId, CancellationToken ct = default);
    string GenerateStrongPassword(int length = 24);
}

/// <summary>
/// #6: Encrypted File &amp; Folder Vault Pro (AES-256-GCM + PBKDF2-SHA256 310,000 iterations).
/// Encrypts individual files OR entire directories (automatically packaged as a compressed archive
/// before AEAD encryption) with SHA-256 integrity verification and strong password generation.
/// </summary>
public sealed class VaultProService : IVaultProService
{
    private const int SaltBytes = 16;
    private const int NonceBytes = 12;
    private const int TagBytes = 16;
    private const int KeyBytes = 32;
    private const int Pbkdf2Iterations = 310_000;
    private static readonly byte[] MagicHeader = Encoding.ASCII.GetBytes("BVLT2");

    private readonly string _vaultDir;
    private readonly string _indexPath;

    public VaultProService(ISettingsService settings)
    {
        _vaultDir = Path.Combine(settings.DataDirectory, "vault-pro");
        _indexPath = Path.Combine(_vaultDir, "index.json");
        Directory.CreateDirectory(_vaultDir);
    }

    public async Task<OperationResult<IReadOnlyList<VaultProItem>>> ListItemsAsync(CancellationToken ct = default)
    {
        var list = await ReadIndexAsync(ct).ConfigureAwait(false);
        return OperationResult<IReadOnlyList<VaultProItem>>.Ok(list, $"{list.Count} encrypted vault item(s).");
    }

    public async Task<OperationResult<VaultProItem>> SealFileOrFolderAsync(string sourcePath, string passphrase, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(sourcePath))
            return OperationResult<VaultProItem>.Fail("Select a file or folder to encrypt.");
        if (string.IsNullOrWhiteSpace(passphrase) || passphrase.Length < 8)
            return OperationResult<VaultProItem>.Fail("Vault passphrase must be at least 8 characters long.");

        bool isDir = Directory.Exists(sourcePath);
        bool isFile = File.Exists(sourcePath);
        if (!isDir && !isFile)
            return OperationResult<VaultProItem>.Fail($"Path does not exist: {sourcePath}");

        string? tempZip = null;
        try
        {
            byte[] plaintext;
            if (isDir)
            {
                tempZip = Path.Combine(Path.GetTempPath(), $"bvlt-stage-{Guid.NewGuid():N}.zip");
                ZipFile.CreateFromDirectory(sourcePath, tempZip, CompressionLevel.Optimal, includeBaseDirectory: true);
                plaintext = await File.ReadAllBytesAsync(tempZip, ct).ConfigureAwait(false);
            }
            else
            {
                plaintext = await File.ReadAllBytesAsync(sourcePath, ct).ConfigureAwait(false);
            }

            var sha256 = Convert.ToHexString(SHA256.HashData(plaintext)).ToLowerInvariant();
            var salt = RandomNumberGenerator.GetBytes(SaltBytes);
            var nonce = RandomNumberGenerator.GetBytes(NonceBytes);
            var key = Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(passphrase), salt, Pbkdf2Iterations, HashAlgorithmName.SHA256, KeyBytes);

            var ciphertext = new byte[plaintext.Length];
            var tag = new byte[TagBytes];
            using (var aes = new AesGcm(key, TagBytes))
            {
                aes.Encrypt(nonce, plaintext, ciphertext, tag, MagicHeader);
            }
            CryptographicOperations.ZeroMemory(key);

            var id = Guid.NewGuid().ToString("N")[..12];
            var vaultFile = Path.Combine(_vaultDir, $"{id}.bvault");
            await using (var fs = File.Create(vaultFile))
            {
                await fs.WriteAsync(MagicHeader, ct).ConfigureAwait(false);
                await fs.WriteAsync(salt, ct).ConfigureAwait(false);
                await fs.WriteAsync(nonce, ct).ConfigureAwait(false);
                await fs.WriteAsync(tag, ct).ConfigureAwait(false);
                await fs.WriteAsync(ciphertext, ct).ConfigureAwait(false);
            }

            var item = new VaultProItem
            {
                Id = id,
                OriginalName = Path.GetFileName(sourcePath.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)),
                IsFolderArchive = isDir,
                PlaintextBytes = plaintext.LongLength,
                EncryptedBytes = new FileInfo(vaultFile).Length,
                Sha256 = sha256,
                SealedAtUtc = DateTimeOffset.UtcNow,
                VaultFilePath = vaultFile
            };

            var list = await ReadIndexAsync(ct).ConfigureAwait(false);
            list.Insert(0, item);
            await WriteIndexAsync(list, ct).ConfigureAwait(false);

            return OperationResult<VaultProItem>.Ok(item, $"Encrypted '{item.OriginalName}' into Vault Pro (AES-256-GCM, SHA-256 verified).");
        }
        catch (Exception ex)
        {
            return OperationResult<VaultProItem>.Fail($"Encryption failed: {ex.Message}");
        }
        finally
        {
            if (tempZip is not null && File.Exists(tempZip))
            {
                try { File.Delete(tempZip); } catch { }
            }
        }
    }

    public async Task<OperationResult<string>> UnsealItemAsync(string itemId, string passphrase, string destinationFolder, CancellationToken ct = default)
    {
        var list = await ReadIndexAsync(ct).ConfigureAwait(false);
        var item = list.FirstOrDefault(i => string.Equals(i.Id, itemId, StringComparison.OrdinalIgnoreCase));
        if (item is null || !File.Exists(item.VaultFilePath))
            return OperationResult<string>.Fail("Vault item not found.");

        try
        {
            var blob = await File.ReadAllBytesAsync(item.VaultFilePath, ct).ConfigureAwait(false);
            int minLen = MagicHeader.Length + SaltBytes + NonceBytes + TagBytes;
            if (blob.Length < minLen || !blob.AsSpan(0, MagicHeader.Length).SequenceEqual(MagicHeader))
                return OperationResult<string>.Fail("Vault file is corrupted or unsupported format.");

            int offset = MagicHeader.Length;
            var salt = blob.AsSpan(offset, SaltBytes).ToArray(); offset += SaltBytes;
            var nonce = blob.AsSpan(offset, NonceBytes).ToArray(); offset += NonceBytes;
            var tag = blob.AsSpan(offset, TagBytes).ToArray(); offset += TagBytes;
            var ciphertext = blob.AsSpan(offset).ToArray();

            var key = Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(passphrase), salt, Pbkdf2Iterations, HashAlgorithmName.SHA256, KeyBytes);
            var plaintext = new byte[ciphertext.Length];
            try
            {
                using var aes = new AesGcm(key, TagBytes);
                aes.Decrypt(nonce, ciphertext, tag, plaintext, MagicHeader);
            }
            catch (CryptographicException)
            {
                return OperationResult<string>.Fail("Incorrect passphrase or tampered vault item (AES-GCM authentication failed).", "BAD_PASSPHRASE");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(key);
            }

            var actualSha = Convert.ToHexString(SHA256.HashData(plaintext)).ToLowerInvariant();
            if (!string.Equals(actualSha, item.Sha256, StringComparison.OrdinalIgnoreCase))
                return OperationResult<string>.Fail("SHA-256 integrity verification failed after decryption.");

            Directory.CreateDirectory(destinationFolder);
            if (item.IsFolderArchive)
            {
                var tmpZip = Path.Combine(Path.GetTempPath(), $"bvlt-unseal-{Guid.NewGuid():N}.zip");
                try
                {
                    await File.WriteAllBytesAsync(tmpZip, plaintext, ct).ConfigureAwait(false);
                    ZipFile.ExtractToDirectory(tmpZip, destinationFolder, overwriteFiles: true);
                }
                finally
                {
                    try { File.Delete(tmpZip); } catch { }
                }
                return OperationResult<string>.Ok(destinationFolder, $"Decrypted & extracted folder archive '{item.OriginalName}' to {destinationFolder}.");
            }
            else
            {
                var outPath = Path.Combine(destinationFolder, item.OriginalName);
                await File.WriteAllBytesAsync(outPath, plaintext, ct).ConfigureAwait(false);
                return OperationResult<string>.Ok(outPath, $"Decrypted & verified file '{item.OriginalName}' to {outPath}.");
            }
        }
        catch (Exception ex)
        {
            return OperationResult<string>.Fail($"Decryption failed: {ex.Message}");
        }
    }

    public async Task<OperationResult> DeleteItemAsync(string itemId, CancellationToken ct = default)
    {
        var list = await ReadIndexAsync(ct).ConfigureAwait(false);
        var item = list.FirstOrDefault(i => string.Equals(i.Id, itemId, StringComparison.OrdinalIgnoreCase));
        if (item is null) return OperationResult.Fail("Vault item not found.");

        try { if (File.Exists(item.VaultFilePath)) File.Delete(item.VaultFilePath); } catch { }
        list.Remove(item);
        await WriteIndexAsync(list, ct).ConfigureAwait(false);
        return OperationResult.Ok($"Removed '{item.OriginalName}' from Vault Pro.");
    }

    public string GenerateStrongPassword(int length = 24)
    {
        length = Math.Clamp(length, 12, 64);
        const string alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*-_=+";
        var chars = new char[length];
        for (int i = 0; i < length; i++)
            chars[i] = alphabet[RandomNumberGenerator.GetInt32(alphabet.Length)];
        return new string(chars);
    }

    private async Task<List<VaultProItem>> ReadIndexAsync(CancellationToken ct)
    {
        if (!File.Exists(_indexPath)) return new List<VaultProItem>();
        try
        {
            var json = await File.ReadAllTextAsync(_indexPath, ct).ConfigureAwait(false);
            return JsonSerializer.Deserialize<List<VaultProItem>>(json) ?? new List<VaultProItem>();
        }
        catch { return new List<VaultProItem>(); }
    }

    private async Task WriteIndexAsync(List<VaultProItem> items, CancellationToken ct)
    {
        Directory.CreateDirectory(_vaultDir);
        var json = JsonSerializer.Serialize(items, new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(_indexPath, json, ct).ConfigureAwait(false);
    }
}
