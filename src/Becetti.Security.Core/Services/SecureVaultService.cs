using System.Security.Cryptography;
using System.Text.Json;
using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

/// <summary>
/// Real AES-256-GCM file encryption, with the master key itself protected by
/// Windows DPAPI (CurrentUser scope) — the same approach TokenStore already
/// uses for cloud tokens. The manifest (file names/sizes) is also DPAPI
/// protected on disk. Nothing here ever leaves this device.
/// </summary>
public sealed class SecureVaultService : ISecureVaultService
{
    private const int NonceSizeBytes = 12;
    private const int TagSizeBytes = 16;

    /// <summary>200 MB — this service loads a whole file into memory for AES-GCM; larger files are reported honestly as too large rather than risking an out-of-memory failure.</summary>
    public const long MaxFileSizeBytes = 200L * 1024 * 1024;

    private readonly IFileShredderService _shredder;
    private readonly string _vaultDir;
    private readonly string _keyPath;
    private readonly string _manifestPath;
    private readonly byte[] _entropy = System.Text.Encoding.UTF8.GetBytes("BECETTI-SECURITY-VAULT-v1");
    private readonly SemaphoreSlim _gate = new(1, 1);

    public SecureVaultService(IFileShredderService shredder, string? dataDirectory = null)
    {
        _shredder = shredder;
        var dir = dataDirectory ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "BecettiSecurity");
        _vaultDir = Path.Combine(dir, "Vault");
        _keyPath = Path.Combine(dir, "vault.key");
        _manifestPath = Path.Combine(dir, "vault-manifest.dat");
    }

    [System.Runtime.Versioning.SupportedOSPlatformGuard("windows")]
    private static bool ProtectionActive => OperatingSystem.IsWindows();

    public bool IsInitialized => File.Exists(_keyPath);

    public async Task<OperationResult> InitializeAsync(CancellationToken ct = default)
    {
        if (IsInitialized)
            return OperationResult.Ok("The vault already exists.");

        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            Directory.CreateDirectory(_vaultDir);
            var key = RandomNumberGenerator.GetBytes(32);
            var toStore = ProtectionActive ? ProtectedData.Protect(key, _entropy, DataProtectionScope.CurrentUser) : key;
            await File.WriteAllBytesAsync(_keyPath, toStore, ct).ConfigureAwait(false);
            await WriteManifestAsync(new List<VaultItemInfo>(), ct).ConfigureAwait(false);

            return OperationResult.Ok(ProtectionActive
                ? "Vault created. Files you add are encrypted with AES-256 and the key is bound to your Windows account on this device."
                : "Vault created. Files you add are encrypted with AES-256 (key protection via DPAPI is only available on Windows).");
        }
        catch (Exception ex)
        {
            return OperationResult.Fail($"Could not create the vault: {ex.Message}", "ERROR");
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<IReadOnlyList<VaultItemInfo>> ListItemsAsync(CancellationToken ct = default)
    {
        if (!IsInitialized)
            return Array.Empty<VaultItemInfo>();

        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            return await ReadManifestAsync(ct).ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<OperationResult> AddFileAsync(string sourcePath, bool shredOriginal, CancellationToken ct = default)
    {
        if (!IsInitialized)
            return OperationResult.Fail("Create the vault first.", "NOT_INITIALIZED");

        if (!File.Exists(sourcePath))
            return OperationResult.Fail("File not found.", "FILE_NOT_FOUND");

        var info = new FileInfo(sourcePath);
        if (info.Length > MaxFileSizeBytes)
            return OperationResult.Fail($"This file is larger than the {MaxFileSizeBytes / (1024 * 1024)} MB the Secure Vault can encrypt at once.", "FILE_TOO_LARGE");

        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var key = await LoadMasterKeyAsync(ct).ConfigureAwait(false);
            var plaintext = await File.ReadAllBytesAsync(sourcePath, ct).ConfigureAwait(false);

            var nonce = RandomNumberGenerator.GetBytes(NonceSizeBytes);
            var tag = new byte[TagSizeBytes];
            var ciphertext = new byte[plaintext.Length];

            using (var aesGcm = new AesGcm(key, TagSizeBytes))
                aesGcm.Encrypt(nonce, plaintext, ciphertext, tag);

            var item = new VaultItemInfo
            {
                OriginalFileName = Path.GetFileName(sourcePath),
                SizeBytes = plaintext.Length
            };

            Directory.CreateDirectory(_vaultDir);
            var blobPath = Path.Combine(_vaultDir, $"{item.Id}.enc");
            await using (var blobStream = new FileStream(blobPath, FileMode.CreateNew, FileAccess.Write))
            {
                await blobStream.WriteAsync(nonce, ct).ConfigureAwait(false);
                await blobStream.WriteAsync(tag, ct).ConfigureAwait(false);
                await blobStream.WriteAsync(ciphertext, ct).ConfigureAwait(false);
            }

            var manifest = await ReadManifestAsync(ct).ConfigureAwait(false);
            var updated = new List<VaultItemInfo>(manifest) { item };
            await WriteManifestAsync(updated, ct).ConfigureAwait(false);

            Array.Clear(plaintext);

            if (shredOriginal)
            {
                var shredResult = await _shredder.ShredFileAsync(sourcePath, ct: ct).ConfigureAwait(false);
                if (!shredResult.Success)
                    return OperationResult.Ok($"File encrypted and added to the vault, but the original could not be securely deleted: {shredResult.Message}");
            }

            return OperationResult.Ok(shredOriginal
                ? "File encrypted, added to the vault, and the original was securely deleted."
                : "File encrypted and added to the vault. The original file was left in place.");
        }
        catch (Exception ex)
        {
            return OperationResult.Fail($"Could not add the file to the vault: {ex.Message}", "ERROR");
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<OperationResult> ExtractFileAsync(Guid itemId, string destinationPath, CancellationToken ct = default)
    {
        if (!IsInitialized)
            return OperationResult.Fail("The vault has not been created yet.", "NOT_INITIALIZED");

        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var manifest = await ReadManifestAsync(ct).ConfigureAwait(false);
            var item = manifest.FirstOrDefault(i => i.Id == itemId);
            if (item is null)
                return OperationResult.Fail("That item is no longer in the vault.", "NOT_FOUND");

            var blobPath = Path.Combine(_vaultDir, $"{item.Id}.enc");
            if (!File.Exists(blobPath))
                return OperationResult.Fail("The vault's encrypted copy of this file is missing.", "BLOB_MISSING");

            var blob = await File.ReadAllBytesAsync(blobPath, ct).ConfigureAwait(false);
            if (blob.Length < NonceSizeBytes + TagSizeBytes)
                return OperationResult.Fail("The vault's encrypted copy of this file is corrupt.", "BLOB_CORRUPT");

            var nonce = blob.AsSpan(0, NonceSizeBytes);
            var tag = blob.AsSpan(NonceSizeBytes, TagSizeBytes);
            var ciphertext = blob.AsSpan(NonceSizeBytes + TagSizeBytes);
            var plaintext = new byte[ciphertext.Length];

            var key = await LoadMasterKeyAsync(ct).ConfigureAwait(false);
            using (var aesGcm = new AesGcm(key, TagSizeBytes))
                aesGcm.Decrypt(nonce, ciphertext, tag, plaintext);

            await File.WriteAllBytesAsync(destinationPath, plaintext, ct).ConfigureAwait(false);
            Array.Clear(plaintext);

            return OperationResult.Ok($"Decrypted \"{item.OriginalFileName}\" to the chosen location. The vault's copy was kept.");
        }
        catch (CryptographicException)
        {
            return OperationResult.Fail("Decryption failed — the vault key on this device no longer matches this file.", "DECRYPT_FAILED");
        }
        catch (Exception ex)
        {
            return OperationResult.Fail($"Could not extract the file: {ex.Message}", "ERROR");
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<OperationResult> DeleteItemAsync(Guid itemId, CancellationToken ct = default)
    {
        if (!IsInitialized)
            return OperationResult.Fail("The vault has not been created yet.", "NOT_INITIALIZED");

        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var manifest = await ReadManifestAsync(ct).ConfigureAwait(false);
            var item = manifest.FirstOrDefault(i => i.Id == itemId);
            if (item is null)
                return OperationResult.Fail("That item is no longer in the vault.", "NOT_FOUND");

            var remaining = manifest.Where(i => i.Id != itemId).ToList();
            await WriteManifestAsync(remaining, ct).ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }

        if (File.Exists(Path.Combine(_vaultDir, $"{itemId}.enc")))
            await _shredder.ShredFileAsync(Path.Combine(_vaultDir, $"{itemId}.enc"), ct: ct).ConfigureAwait(false);

        return OperationResult.Ok("Removed from the vault.");
    }

    private async Task<byte[]> LoadMasterKeyAsync(CancellationToken ct)
    {
        var bytes = await File.ReadAllBytesAsync(_keyPath, ct).ConfigureAwait(false);
        return ProtectionActive ? ProtectedData.Unprotect(bytes, _entropy, DataProtectionScope.CurrentUser) : bytes;
    }

    private async Task<List<VaultItemInfo>> ReadManifestAsync(CancellationToken ct)
    {
        if (!File.Exists(_manifestPath))
            return new List<VaultItemInfo>();

        var bytes = await File.ReadAllBytesAsync(_manifestPath, ct).ConfigureAwait(false);
        if (bytes.Length == 0)
            return new List<VaultItemInfo>();

        if (ProtectionActive)
            bytes = ProtectedData.Unprotect(bytes, _entropy, DataProtectionScope.CurrentUser);

        try
        {
            return JsonSerializer.Deserialize<List<VaultItemInfo>>(bytes) ?? new List<VaultItemInfo>();
        }
        catch
        {
            return new List<VaultItemInfo>();
        }
    }

    private async Task WriteManifestAsync(List<VaultItemInfo> items, CancellationToken ct)
    {
        var json = JsonSerializer.SerializeToUtf8Bytes(items);
        var toStore = ProtectionActive ? ProtectedData.Protect(json, _entropy, DataProtectionScope.CurrentUser) : json;
        Directory.CreateDirectory(Path.GetDirectoryName(_manifestPath)!);
        await File.WriteAllBytesAsync(_manifestPath, toStore, ct).ConfigureAwait(false);
    }
}
