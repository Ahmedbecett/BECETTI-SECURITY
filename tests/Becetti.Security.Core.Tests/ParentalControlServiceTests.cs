using Becetti.Security.Core.Services;

namespace Becetti.Security.Core.Tests;

/// <summary>
/// Exercises ParentalControlService against a throwaway hosts-file-shaped
/// text file (never the real Windows hosts file). Block/unblock require
/// Administrator by design, so those two tests assert whichever real
/// outcome actually applies to the account running the test — they do not
/// assume elevation either way.
/// </summary>
public sealed class ParentalControlServiceTests : IDisposable
{
    private readonly string _hostsPath;

    public ParentalControlServiceTests()
    {
        _hostsPath = Path.Combine(Path.GetTempPath(), $"becetti-hosts-{Guid.NewGuid()}.txt");
    }

    public void Dispose()
    {
        try { if (File.Exists(_hostsPath)) File.Delete(_hostsPath); }
        catch { /* best-effort cleanup */ }
    }

    [Fact]
    public async Task GetBlockedDomainsAsync_NoFile_ReturnsEmptyList()
    {
        var service = new ParentalControlService(_hostsPath);

        var result = await service.GetBlockedDomainsAsync();

        Assert.True(result.Success);
        Assert.Empty(result.Value!);
    }

    [Fact]
    public async Task GetBlockedDomainsAsync_ParsesOnlyBecettiTaggedLines()
    {
        await File.WriteAllLinesAsync(_hostsPath, new[]
        {
            "127.0.0.1 localhost",
            "0.0.0.0 example.com # BECETTI-PARENTAL",
            "0.0.0.0 unrelated-entry.test",
            "0.0.0.0 blocked-site.test # BECETTI-PARENTAL"
        });

        var service = new ParentalControlService(_hostsPath);
        var result = await service.GetBlockedDomainsAsync();

        Assert.True(result.Success);
        var domains = result.Value!.Select(d => d.Domain).ToList();
        Assert.Equal(2, domains.Count);
        Assert.Contains("example.com", domains);
        Assert.Contains("blocked-site.test", domains);
        Assert.DoesNotContain("unrelated-entry.test", domains);
    }

    [Fact]
    public async Task BlockDomainAsync_EmptyDomain_ReturnsBadRequest()
    {
        var service = new ParentalControlService(_hostsPath);

        var result = await service.BlockDomainAsync("   ");

        Assert.False(result.Success);
        Assert.Equal("BAD_REQUEST", result.ErrorCode);
    }

    [Fact]
    public async Task BlockDomainAsync_RealOutcome_MatchesCurrentElevationState()
    {
        var service = new ParentalControlService(_hostsPath);

        var result = await service.BlockDomainAsync("block-me.test");

        if (service.CanManageBlocklist)
        {
            Assert.True(result.Success, result.Message);
            var listed = await service.GetBlockedDomainsAsync();
            Assert.Contains(listed.Value!, d => d.Domain == "block-me.test");
        }
        else
        {
            Assert.False(result.Success);
            Assert.Equal("ELEVATION_REQUIRED", result.ErrorCode);
        }
    }

    [Fact]
    public async Task UnblockDomainAsync_NotBlocked_RealOutcomeMatchesElevationState()
    {
        var service = new ParentalControlService(_hostsPath);

        var result = await service.UnblockDomainAsync("never-blocked.test");

        if (service.CanManageBlocklist)
            Assert.True(result.Success, result.Message);
        else
            Assert.Equal("ELEVATION_REQUIRED", result.ErrorCode);
    }
}
