using Becetti.Security.Core.Services;

namespace Becetti.Security.Core.Tests;

public sealed class WifiSecurityServiceTests
{
    [Fact]
    public void ParseNetshOutput_ConnectedWpa2Network_ParsesAllFields()
    {
        const string output =
            "There is 1 interface on the system:\r\n\r\n" +
            "    Name                   : Wi-Fi\r\n" +
            "    Description            : Intel(R) Wi-Fi 6 AX201\r\n" +
            "    State                  : connected\r\n" +
            "    SSID                   : HomeNetwork\r\n" +
            "    Network type           : Infrastructure\r\n" +
            "    Authentication         : WPA2-Personal\r\n" +
            "    Cipher                 : CCMP\r\n" +
            "    Signal                 : 87%\r\n";

        var info = WifiSecurityService.ParseNetshOutput(output);

        Assert.True(info.Connected);
        Assert.Equal("HomeNetwork", info.Ssid);
        Assert.Equal("WPA2-Personal", info.AuthenticationType);
        Assert.Equal("CCMP", info.CipherType);
        Assert.Equal(87, info.SignalPercent);
        Assert.True(info.IsStronglySecured);
    }

    [Fact]
    public void ParseNetshOutput_OpenNetwork_IsNotStronglySecured()
    {
        const string output =
            "    State                  : connected\r\n" +
            "    SSID                   : CoffeeShopWiFi\r\n" +
            "    Authentication         : Open\r\n" +
            "    Cipher                 : None\r\n";

        var info = WifiSecurityService.ParseNetshOutput(output);

        Assert.True(info.Connected);
        Assert.False(info.IsStronglySecured);
    }

    [Fact]
    public void ParseNetshOutput_Disconnected_ReturnsNotConnectedRatherThanStaleData()
    {
        const string output = "    State                  : disconnected\r\n";

        var info = WifiSecurityService.ParseNetshOutput(output);

        Assert.False(info.Connected);
        Assert.Null(info.Ssid);
    }
}
