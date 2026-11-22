using Becetti.Security.Core.Services;

namespace Becetti.Security.Core.Tests;

/// <summary>
/// Exercises SecureVaultService's real AES-256-GCM encrypt/decrypt round
/// trip against actual files on disk, using a throwaway data directory per
/// test so tests never touch the real %LocalAppData% vault.
/// </summary>
public sealed class SecureVaultServiceTests : IDisposable
{
    private readonly string _dataDir;
    private readonly SecureVaultService _vault;

    public SecureVaultServiceTests()
    {
        _dataDir = Path.Combine(Path.GetTempPath(), $"becetti-vault-{Guid.NewGuid()}");
        _vault = new SecureVaultService(new FileShredderService(), _dataDir);
    }

    public void Dispose()
    {
        try { if (Directory.Exists(_dataDir)) Directory.Delete(_dataDir, recursive: true); }
        catch { /* best-effort cleanup */ }
    }

    [Fact]
    public async Task IsInitialized_BeforeInitializeAsync_IsFalse()
    {
        Assert.False(_vault.IsInitialized);
    }

    [Fact]
    public async Task InitializeAsync_CreatesVaultKey_AndIsIdempotent()
    {
        var first = await _vault.InitializeAsync();
        Assert.True(first.Success, first.Message);
        Assert.True(_vault.IsInitialized);

        var second = await _vault.InitializeAsync();
        Assert.True(second.Success);
    }

    [Fact]
    public async Task AddFileAsync_ThenExtractFileAsync_RoundTripsOriginalBytesExactly()
    {
        await _vault.InitializeAsync();

        var sourcePath = Path.Combine(Path.GetTempPath(), $"becetti-vault-src-{Guid.NewGuid()}.txt");
        const string originalContent = "This is a secret document that must round-trip exactly.";
        await File.WriteAllTextAsync(sourcePath, originalContent);

        var addResult = await _vault.AddFileAsync(sourcePath, shredOriginal: false);
        Assert.True(addResult.Success, addResult.Message);
        Assert.True(File.Exists(sourcePath)); // original kept, as requested

        var items = await _vault.ListItemsAsync();
        Assert.Single(items);
        var item = items[0];
        Assert.Equal(Path.GetFileName(sourcePath), item.OriginalFileName);
        Assert.Equal(originalContent.Length, item.SizeBytes);

        var destPath = Path.Combine(Path.GetTempPath(), $"becetti-vault-dest-{Guid.NewGuid()}.txt");
        var extractResult = await _vault.ExtractFileAsync(item.Id, destPath);
        Assert.True(extractResult.Success, extractResult.Message);

        var extractedContent = await File.ReadAllTextAsync(destPath);
        Assert.Equal(originalContent, extractedContent);

        File.Delete(sourcePath);
        File.Delete(destPath);
    }

    [Fact]
    public async Task AddFileAsync_WithShredOriginal_DeletesTheSourceFile()
    {
        await _vault.InitializeAsync();

        var sourcePath = Path.Combine(Path.GetTempPath(), $"becetti-vault-shred-{Guid.NewGuid()}.txt");
        await File.WriteAllTextAsync(sourcePath, "goodbye plaintext");

        var addResult = await _vault.AddFileAsync(sourcePath, shredOriginal: true);

        Assert.True(addResult.Success, addResult.Message);
        Assert.False(File.Exists(sourcePath));
    }

    [Fact]
    public async Task DeleteItemAsync_RemovesItemFromList()
    {
        await _vault.InitializeAsync();

        var sourcePath = Path.Combine(Path.GetTempPath(), $"becetti-vault-del-{Guid.NewGuid()}.txt");
        await File.WriteAllTextAsync(sourcePath, "temporary");
        await _vault.AddFileAsync(sourcePath, shredOriginal: true);

        var items = await _vault.ListItemsAsync();
        var item = Assert.Single(items);

        var deleteResult = await _vault.DeleteItemAsync(item.Id);
        Assert.True(deleteResult.Success, deleteResult.Message);

        var afterDelete = await _vault.ListItemsAsync();
        Assert.Empty(afterDelete);
    }

    [Fact]
    public async Task ExtractFileAsync_UnknownItemId_ReturnsNotFound()
    {
        await _vault.InitializeAsync();

        var result = await _vault.ExtractFileAsync(Guid.NewGuid(), Path.Combine(Path.GetTempPath(), "nope.txt"));

        Assert.False(result.Success);
        Assert.Equal("NOT_FOUND", result.ErrorCode);
    }

    [Fact]
    public async Task AddFileAsync_BeforeInitialize_ReturnsNotInitialized()
    {
        var sourcePath = Path.Combine(Path.GetTempPath(), $"becetti-vault-noinit-{Guid.NewGuid()}.txt");
        await File.WriteAllTextAsync(sourcePath, "x");

        var result = await _vault.AddFileAsync(sourcePath, shredOriginal: false);

        Assert.False(result.Success);
        Assert.Equal("NOT_INITIALIZED", result.ErrorCode);

        File.Delete(sourcePath);
    }
}
