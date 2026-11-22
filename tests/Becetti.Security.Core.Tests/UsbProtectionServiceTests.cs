using Becetti.Security.Core.Services;

namespace Becetti.Security.Core.Tests;

public sealed class UsbProtectionServiceTests
{
    [Fact]
    public void InterpretRemovableBlocked_NoValue_ReturnsNullRatherThanGuessing()
    {
        Assert.Null(UsbProtectionService.InterpretRemovableBlocked(null));
    }

    [Theory]
    [InlineData(0x4, true)]
    [InlineData(0xFF, true)]
    [InlineData(0x1, false)]
    [InlineData(0x0, false)]
    public void InterpretRemovableBlocked_ChecksOnlyTheRemovableBit(int raw, bool expectedBlocked)
    {
        Assert.Equal(expectedBlocked, UsbProtectionService.InterpretRemovableBlocked(raw));
    }

    [Fact]
    public void InterpretAutorunInfDisabled_NoValue_ReturnsNullRatherThanGuessing()
    {
        Assert.Null(UsbProtectionService.InterpretAutorunInfDisabled(null));
    }

    [Theory]
    [InlineData(1, true)]
    [InlineData(0, false)]
    public void InterpretAutorunInfDisabled_MatchesRawDword(int raw, bool expected)
    {
        Assert.Equal(expected, UsbProtectionService.InterpretAutorunInfDisabled(raw));
    }

    [Fact]
    public void ApplyRemovableBit_Enable_SetsBitWithoutClearingOthers()
    {
        // 0x20 = an administrator already disabled autorun for CD-ROM drives.
        var updated = UsbProtectionService.ApplyRemovableBit(0x20, blockRemovable: true);
        Assert.Equal(0x24, updated);
    }

    [Fact]
    public void ApplyRemovableBit_Disable_ClearsOnlyTheRemovableBit()
    {
        var updated = UsbProtectionService.ApplyRemovableBit(0x24, blockRemovable: false);
        Assert.Equal(0x20, updated);
    }

    [Fact]
    public async Task GetConnectedDrivesAsync_NeverThrows_EvenWhenNoRemovableDrivesExist()
    {
        var service = new UsbProtectionService();
        var result = await service.GetConnectedDrivesAsync();

        Assert.True(result.Success);
        Assert.NotNull(result.Value);
    }
}
