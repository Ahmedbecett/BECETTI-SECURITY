using Becetti.Security.Core.Services;

namespace Becetti.Security.Core.Tests;

public sealed class BackupAdvisorServiceTests
{
    [Fact]
    public void ParseJson_FileHistoryRunningWithRestorePoints_ParsesBothSections()
    {
        const string json = "{" +
            "\"FileHistory\":{\"Available\":true,\"Configured\":true}," +
            "\"Restore\":{\"Available\":true,\"Count\":3,\"Latest\":\"2026-11-15T10:00:00Z\"}" +
            "}";

        var status = BackupAdvisorService.ParseJson(json);

        Assert.True(status.Available);
        Assert.True(status.FileHistoryConfigured);
        Assert.Equal(3, status.RestorePointCount);
        Assert.NotNull(status.LatestRestorePoint);
    }

    [Fact]
    public void ParseJson_FileHistoryUnavailable_SurfacesRealErrorRatherThanGuessing()
    {
        const string json = "{" +
            "\"FileHistory\":{\"Available\":false,\"Error\":\"Service fhsvc was not found.\"}," +
            "\"Restore\":{\"Available\":true,\"Count\":0,\"Latest\":null}" +
            "}";

        var status = BackupAdvisorService.ParseJson(json);

        Assert.Null(status.FileHistoryConfigured);
        Assert.Equal("Service fhsvc was not found.", status.RawError);
        Assert.Equal(0, status.RestorePointCount);
    }

    [Fact]
    public void ParseJson_EmptyString_ReturnsUnavailableRatherThanThrowing()
    {
        var status = BackupAdvisorService.ParseJson(string.Empty);

        Assert.False(status.Available);
    }
}
