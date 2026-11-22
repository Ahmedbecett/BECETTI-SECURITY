using Becetti.Security.Core.Models;
using Becetti.Security.Core.Services;

namespace Becetti.Security.Core.Tests;

public sealed class ScheduledScanServiceTests
{
    [Fact]
    public void ParseQueryOutput_QuickScanTask_ParsesFieldsAndDefaultsToQuick()
    {
        const string output =
            "Folder: \\\r\n" +
            "HostName:                             DESKTOP\r\n" +
            "TaskName:                             \\BecettiSecurity_ScheduledScan\r\n" +
            "Task To Run:                          \"C:\\Program Files\\Windows Defender\\MpCmdRun.exe\" -Scan -ScanType 1\r\n" +
            "Schedule Type:                        Daily\r\n" +
            "Start Time:                            03:00:00\r\n" +
            "Next Run Time:                        11/21/2026 3:00:00 AM\r\n" +
            "Last Run Time:                         N/A\r\n" +
            "Last Result:                           267011\r\n";

        var info = ScheduledScanService.ParseQueryOutput(output);

        Assert.True(info.Exists);
        Assert.Equal(DefenderScanType.Quick, info.ScanType);
        Assert.Equal("267011", info.LastTaskResult);
        Assert.Null(info.LastRunTime);
        Assert.NotNull(info.NextRunTime);
    }

    [Fact]
    public void ParseQueryOutput_FullScanTaskToRun_IsRecognizedAsFull()
    {
        const string output =
            "Task To Run:                          \"C:\\Program Files\\Windows Defender\\MpCmdRun.exe\" -Scan -ScanType 2\r\n" +
            "Schedule Type:                        Daily\r\n" +
            "Start Time:                            22:00:00\r\n";

        var info = ScheduledScanService.ParseQueryOutput(output);

        Assert.Equal(DefenderScanType.Full, info.ScanType);
    }
}
