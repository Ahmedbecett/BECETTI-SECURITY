using Becetti.Security.Core.Models;
using Becetti.Security.Core.Services;

namespace Becetti.Security.Core.Tests;

public sealed class ThreatIntelHistoryServiceTests
{
    [Fact]
    public async Task RecordAndRead_NewestFirst()
    {
        var dir = Path.Combine(Path.GetTempPath(), "becetti-test-" + Guid.NewGuid());
        try
        {
            var history = new ThreatIntelHistoryService(dir);
            await history.RecordAsync(new ThreatIntelScanRecord
            {
                TargetType = ThreatIntelTargetType.File,
                TargetDisplay = "sample.exe",
                Sha256 = "abc123",
                Verdict = ThreatIntelVerdict.Clean,
                DetectionRatio = "0/72"
            });
            await history.RecordAsync(new ThreatIntelScanRecord
            {
                TargetType = ThreatIntelTargetType.Url,
                TargetDisplay = "https://example.com/",
                Verdict = ThreatIntelVerdict.Malicious,
                DetectionRatio = "5/72",
                Permalink = "https://www.virustotal.com/gui/url/abc"
            });

            var records = await history.ReadRecentAsync(10);

            Assert.Equal(2, records.Count);
            Assert.Equal(ThreatIntelTargetType.Url, records[0].TargetType);
            Assert.Equal(ThreatIntelVerdict.Malicious, records[0].Verdict);
            Assert.Equal(ThreatIntelTargetType.File, records[1].TargetType);
        }
        finally
        {
            if (Directory.Exists(dir))
                Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public async Task ReadRecentAsync_Empty_ReturnsEmpty()
    {
        var dir = Path.Combine(Path.GetTempPath(), "becetti-test-" + Guid.NewGuid());
        var history = new ThreatIntelHistoryService(dir);
        Assert.Empty(await history.ReadRecentAsync());
    }

    [Fact]
    public async Task ReadRecentAsync_RespectsCountLimit()
    {
        var dir = Path.Combine(Path.GetTempPath(), "becetti-test-" + Guid.NewGuid());
        try
        {
            var history = new ThreatIntelHistoryService(dir);
            for (var i = 0; i < 5; i++)
            {
                await history.RecordAsync(new ThreatIntelScanRecord
                {
                    TargetType = ThreatIntelTargetType.File,
                    TargetDisplay = $"file{i}.exe",
                    Verdict = ThreatIntelVerdict.Clean,
                    DetectionRatio = "0/72"
                });
            }

            var records = await history.ReadRecentAsync(2);
            Assert.Equal(2, records.Count);
            Assert.Equal("file4.exe", records[0].TargetDisplay);
        }
        finally
        {
            if (Directory.Exists(dir))
                Directory.Delete(dir, recursive: true);
        }
    }
}
