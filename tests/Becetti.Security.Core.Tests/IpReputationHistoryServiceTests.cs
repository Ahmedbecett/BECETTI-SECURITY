using Becetti.Security.Core.Models;
using Becetti.Security.Core.Services;

namespace Becetti.Security.Core.Tests;

public sealed class IpReputationHistoryServiceTests
{
    [Fact]
    public async Task RecordAndRead_NewestFirst()
    {
        var dir = Path.Combine(Path.GetTempPath(), "becetti-test-" + Guid.NewGuid());
        try
        {
            var history = new IpReputationHistoryService(dir);
            await history.RecordAsync(new IpReputationCheckRecord
            {
                IpAddress = "1.1.1.1",
                AbuseConfidenceScore = 0,
                Verdict = IpReputationVerdict.Clean
            });
            await history.RecordAsync(new IpReputationCheckRecord
            {
                IpAddress = "118.25.6.39",
                AbuseConfidenceScore = 100,
                Verdict = IpReputationVerdict.Malicious
            });

            var records = await history.ReadRecentAsync(10);

            Assert.Equal(2, records.Count);
            Assert.Equal("118.25.6.39", records[0].IpAddress);
            Assert.Equal(IpReputationVerdict.Malicious, records[0].Verdict);
            Assert.Equal("1.1.1.1", records[1].IpAddress);
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
        var history = new IpReputationHistoryService(dir);
        Assert.Empty(await history.ReadRecentAsync());
    }

    [Fact]
    public async Task ReadRecentAsync_RespectsCountLimit()
    {
        var dir = Path.Combine(Path.GetTempPath(), "becetti-test-" + Guid.NewGuid());
        try
        {
            var history = new IpReputationHistoryService(dir);
            for (var i = 0; i < 5; i++)
            {
                await history.RecordAsync(new IpReputationCheckRecord
                {
                    IpAddress = $"10.0.0.{i}",
                    AbuseConfidenceScore = 0,
                    Verdict = IpReputationVerdict.Clean
                });
            }

            var records = await history.ReadRecentAsync(2);
            Assert.Equal(2, records.Count);
            Assert.Equal("10.0.0.4", records[0].IpAddress);
        }
        finally
        {
            if (Directory.Exists(dir))
                Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void StatusLabel_ReflectsVerdict()
    {
        var malicious = new IpReputationCheckRecord { IpAddress = "1.2.3.4", AbuseConfidenceScore = 90, Verdict = IpReputationVerdict.Malicious };
        var clean = new IpReputationCheckRecord { IpAddress = "1.1.1.1", AbuseConfidenceScore = 0, Verdict = IpReputationVerdict.Clean };

        Assert.False(malicious.IsClean);
        Assert.Contains("Malicious", malicious.StatusLabel);
        Assert.True(clean.IsClean);
        Assert.Equal("Clean", clean.StatusLabel);
    }
}
