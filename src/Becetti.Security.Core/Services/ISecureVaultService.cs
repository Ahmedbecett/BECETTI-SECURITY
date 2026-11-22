using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

/// <summary>
/// Local, encrypted storage for files the user explicitly chooses to
/// protect. Every file is encrypted with AES-256-GCM; the encryption key
/// itself is protected with Windows DPAPI (bound to this user account on
/// this machine), the same mechanism BECETTI SECURITY already uses for
/// cloud tokens. Nothing here is uploaded anywhere — this is purely local
/// storage, independent of Cloud Sync.
/// </summary>
public interface ISecureVaultService
{
    /// <summary>True once a vault key already exists on this device.</summary>
    bool IsInitialized { get; }

    /// <summary>Creates the vault's encryption key. Safe to call once; a no-op if already initialized.</summary>
    Task<OperationResult> InitializeAsync(CancellationToken ct = default);

    Task<IReadOnlyList<VaultItemInfo>> ListItemsAsync(CancellationToken ct = default);

    /// <summary>
    /// Encrypts the file at <paramref name="sourcePath"/> into the vault.
    /// When <paramref name="shredOriginal"/> is true, the original plaintext
    /// file is securely overwritten and deleted afterward so it is not left
    /// behind unencrypted at its original location.
    /// </summary>
    Task<OperationResult> AddFileAsync(string sourcePath, bool shredOriginal, CancellationToken ct = default);

    /// <summary>Decrypts a vault item out to <paramref name="destinationPath"/>. The vault copy is kept.</summary>
    Task<OperationResult> ExtractFileAsync(Guid itemId, string destinationPath, CancellationToken ct = default);

    /// <summary>Permanently removes an item from the vault (the encrypted blob is overwritten, then deleted).</summary>
    Task<OperationResult> DeleteItemAsync(Guid itemId, CancellationToken ct = default);
}
