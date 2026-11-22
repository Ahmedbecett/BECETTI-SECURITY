using Becetti.Security.Core.Services;

namespace Becetti.Security.Core.Tests;

public sealed class StartupManagerServiceTests
{
    [Fact]
    public void ParseApprovedEnabled_MissingValue_MeansEnabled()
    {
        Assert.True(StartupManagerService.ParseApprovedEnabled(null));
        Assert.True(StartupManagerService.ParseApprovedEnabled(Array.Empty<byte>()));
    }

    [Theory]
    [InlineData(0x02)]
    [InlineData(0x06)]
    public void ParseApprovedEnabled_KnownEnabledBytes_MeanEnabled(byte firstByte)
    {
        var data = new byte[12];
        data[0] = firstByte;
        Assert.True(StartupManagerService.ParseApprovedEnabled(data));
    }

    [Fact]
    public void ParseApprovedEnabled_0x03_MeansDisabled()
    {
        var data = new byte[12];
        data[0] = 0x03;
        Assert.False(StartupManagerService.ParseApprovedEnabled(data));
    }

    [Fact]
    public void BuildApprovedValue_Enabled_RoundTripsThroughParser()
    {
        var value = StartupManagerService.BuildApprovedValue(enabled: true);
        Assert.Equal(12, value.Length);
        Assert.Equal(0x02, value[0]);
        Assert.True(StartupManagerService.ParseApprovedEnabled(value));
    }

    [Fact]
    public void BuildApprovedValue_Disabled_RoundTripsThroughParser()
    {
        var value = StartupManagerService.BuildApprovedValue(enabled: false);
        Assert.Equal(12, value.Length);
        Assert.Equal(0x03, value[0]);
        Assert.False(StartupManagerService.ParseApprovedEnabled(value));

        // Bytes 4-11 should carry a non-zero FILETIME timestamp of when it was disabled.
        var fileTimeBytes = value[4..12];
        Assert.Contains(fileTimeBytes, b => b != 0);
    }
}
