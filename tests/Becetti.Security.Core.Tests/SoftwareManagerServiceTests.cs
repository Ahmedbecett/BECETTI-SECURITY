using Becetti.Security.Core.Services;

namespace Becetti.Security.Core.Tests;

public sealed class SoftwareManagerServiceTests
{
    [Fact]
    public void ParseInstallDate_ValidEightDigitString_Parses()
    {
        var parsed = SoftwareManagerService.ParseInstallDate("20240315");
        Assert.NotNull(parsed);
        Assert.Equal(2024, parsed!.Value.Year);
        Assert.Equal(3, parsed.Value.Month);
        Assert.Equal(15, parsed.Value.Day);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("2024")]
    [InlineData("not-a-date")]
    [InlineData("20241332")]
    public void ParseInstallDate_InvalidInput_ReturnsNullRatherThanGuessing(string? raw)
    {
        Assert.Null(SoftwareManagerService.ParseInstallDate(raw));
    }
}
