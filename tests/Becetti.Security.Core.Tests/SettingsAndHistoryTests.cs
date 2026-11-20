using Becetti.Security.Core.Services;

namespace Becetti.Security.Core.Tests;

public sealed class SettingsAndHistoryTests
{
    [Fact]
    public async Task Settings_RoundTrip()
    {
        var dir = Path.Combine(Path.GetTempPath(), "becetti-test-" + Guid.NewGuid());
        try
        {
            var first = new SettingsService(dir);
            await first.LoadAsync();
            first.Current.ApiBaseUrl = "https://api.example.test";
            first.Current.Language = "ar";
            first.Current.TelemetryOptIn = true;
            await first.SaveAsync();

            var second = new SettingsService(dir);
            await second.LoadAsync();
            Assert.Equal("https://api.example.test", second.Current.ApiBaseUrl);
            Assert.Equal("ar", second.Current.Language);
            Assert.True(second.Current.TelemetryOptIn);
        }
        finally
        {
            if (Directory.Exists(dir))
                Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public async Task EventLog_RecordAndRead_NewestFirst()
    {
        var dir = Path.Combine(Path.GetTempPath(), "becetti-test-" + Guid.NewGuid());
        try
        {
            var log = new EventLogService(dir);
            await log.RecordAsync("scan.completed", "Quick scan done", true);
            await log.RecordAsync("scan.failed", "Full scan failed", false, "exit 1");

            var events = await log.ReadRecentAsync(10);
            Assert.Equal(2, events.Count);
            Assert.Equal("scan.failed", events[0].Type);
            Assert.Equal("scan.completed", events[1].Type);
        }
        finally
        {
            if (Directory.Exists(dir))
                Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public async Task EventLog_Empty_ReturnsEmpty()
    {
        var dir = Path.Combine(Path.GetTempPath(), "becetti-test-" + Guid.NewGuid());
        var log = new EventLogService(dir);
        Assert.Empty(await log.ReadRecentAsync());
    }
}
