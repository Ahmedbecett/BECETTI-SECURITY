using Becetti.Security.Core.Services;

namespace Becetti.Security.Core.Tests;

public sealed class DriverMonitorServiceTests
{
    [Fact]
    public void ParseWmiDate_ValidDmtfString_Parses()
    {
        // Real Win32_PnPSignedDriver.DriverDate format: yyyyMMddHHmmss.ffffff(+|-)UUU
        var parsed = DriverMonitorService.ParseWmiDate("20230615000000.000000-000");
        Assert.NotNull(parsed);
        Assert.Equal(2023, parsed!.Value.Year);
        Assert.Equal(6, parsed.Value.Month);
        Assert.Equal(15, parsed.Value.Day);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not-a-wmi-date")]
    public void ParseWmiDate_InvalidInput_ReturnsNullRatherThanGuessing(string? raw)
    {
        Assert.Null(DriverMonitorService.ParseWmiDate(raw));
    }
}
