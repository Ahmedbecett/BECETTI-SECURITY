using Becetti.Security.Core.Services;

namespace Becetti.Security.Core.Tests;

/// <summary>
/// Exercises FileShredderService against real temporary files on disk — no
/// mocking of file I/O, since the whole point of this service is what it
/// actually does to real bytes.
/// </summary>
public sealed class FileShredderServiceTests
{
    [Fact]
    public async Task ShredFileAsync_ExistingFile_OverwritesAndDeletesIt()
    {
        var path = Path.Combine(Path.GetTempPath(), $"becetti-shred-{Guid.NewGuid()}.tmp");
        await File.WriteAllTextAsync(path, "sensitive content that must not survive");

        var shredder = new FileShredderService();
        var result = await shredder.ShredFileAsync(path, passes: 2);

        Assert.True(result.Success, result.Message);
        Assert.False(File.Exists(path));
    }

    [Fact]
    public async Task ShredFileAsync_MissingFile_ReturnsFileNotFound()
    {
        var path = Path.Combine(Path.GetTempPath(), $"becetti-shred-missing-{Guid.NewGuid()}.tmp");
        var shredder = new FileShredderService();

        var result = await shredder.ShredFileAsync(path);

        Assert.False(result.Success);
        Assert.Equal("FILE_NOT_FOUND", result.ErrorCode);
    }

    [Fact]
    public async Task ShredFileAsync_EmptyPath_ReturnsBadRequest()
    {
        var shredder = new FileShredderService();

        var result = await shredder.ShredFileAsync("");

        Assert.False(result.Success);
        Assert.Equal("BAD_REQUEST", result.ErrorCode);
    }

    [Fact]
    public async Task ShredFileAsync_ZeroLengthFile_StillDeletesSuccessfully()
    {
        var path = Path.Combine(Path.GetTempPath(), $"becetti-shred-empty-{Guid.NewGuid()}.tmp");
        await File.WriteAllBytesAsync(path, Array.Empty<byte>());

        var shredder = new FileShredderService();
        var result = await shredder.ShredFileAsync(path);

        Assert.True(result.Success, result.Message);
        Assert.False(File.Exists(path));
    }
}
