using Becetti.Security.Core.Services;

namespace Becetti.Security.Core.Tests;

public sealed class FileHashServiceTests
{
    [Fact]
    public async Task ComputeSha256_KnownVector()
    {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".txt");
        await File.WriteAllTextAsync(path, "abc");

        try
        {
            var hash = await FileHashService.ComputeSha256Async(path);
            // SHA-256("abc") — well-known test vector.
            Assert.Equal("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", hash);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task ComputeSha256_MissingFile_Throws()
    {
        await Assert.ThrowsAsync<FileNotFoundException>(() =>
            FileHashService.ComputeSha256Async(Path.Combine(Path.GetTempPath(), "does-not-exist-" + Guid.NewGuid())));
    }

    [Theory]
    [InlineData("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", true)]
    [InlineData("BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD", true)]
    [InlineData("abc", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    [InlineData("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", false)]
    public void IsValidSha256_Cases(string? value, bool expected)
    {
        Assert.Equal(expected, FileHashService.IsValidSha256(value));
    }
}
