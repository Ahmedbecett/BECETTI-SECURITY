using Becetti.Security.Core.Services;

namespace Becetti.Security.Core.Tests;

public sealed class NetworkMonitorServiceTests
{
    [Fact]
    public void ParseConnectionsJson_EmptyString_MeansNoConnectionsRatherThanFailure()
    {
        var result = NetworkMonitorService.ParseConnectionsJson(string.Empty);

        Assert.True(result.Success);
        Assert.NotNull(result.Value);
        Assert.Empty(result.Value!);
    }

    [Fact]
    public void ParseConnectionsJson_SingleObject_PowerShellCollapseQuirk_ParsesAsOneItem()
    {
        const string json = "{\"LocalAddress\":\"0.0.0.0\",\"LocalPort\":445,\"RemoteAddress\":\"0.0.0.0\",\"RemotePort\":0,\"State\":\"Listen\",\"OwningProcess\":4,\"ProcessName\":\"System\"}";

        var result = NetworkMonitorService.ParseConnectionsJson(json);

        Assert.True(result.Success);
        var item = Assert.Single(result.Value!);
        Assert.Equal("0.0.0.0", item.LocalAddress);
        Assert.Equal(445, item.LocalPort);
        Assert.Equal("Listen", item.State);
        Assert.Equal("System", item.ProcessName);
        Assert.Equal(4, item.OwningProcessId);
    }

    [Fact]
    public void ParseConnectionsJson_Array_ParsesEveryItem()
    {
        const string json = "[" +
            "{\"LocalAddress\":\"192.168.1.5\",\"LocalPort\":51000,\"RemoteAddress\":\"93.184.216.34\",\"RemotePort\":443,\"State\":\"Established\",\"OwningProcess\":1234,\"ProcessName\":\"msedge\"}," +
            "{\"LocalAddress\":\"0.0.0.0\",\"LocalPort\":135,\"RemoteAddress\":\"0.0.0.0\",\"RemotePort\":0,\"State\":\"Listen\",\"OwningProcess\":900,\"ProcessName\":\"svchost\"}" +
            "]";

        var result = NetworkMonitorService.ParseConnectionsJson(json);

        Assert.True(result.Success);
        Assert.Equal(2, result.Value!.Count);
        Assert.Contains(result.Value, c => c.ProcessName == "msedge" && c.State == "Established");
        Assert.Contains(result.Value, c => c.ProcessName == "svchost" && c.State == "Listen");
    }

    [Fact]
    public void ParseConnectionsJson_FailureMarkerObject_ReturnsFailureRatherThanEmptyList()
    {
        const string json = "{\"Available\":false,\"Error\":\"The term 'Get-NetTCPConnection' is not recognized.\"}";

        var result = NetworkMonitorService.ParseConnectionsJson(json);

        Assert.False(result.Success);
        Assert.Contains("Get-NetTCPConnection", result.Message);
    }

    [Fact]
    public void ToAdapterInfo_NeverThrows_ForRealLocalInterfaces()
    {
        foreach (var nic in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
        {
            var info = NetworkMonitorService.ToAdapterInfo(nic);
            Assert.False(string.IsNullOrEmpty(info.Name));
        }
    }
}
