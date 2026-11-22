using Becetti.Security.Core.Services;

namespace Becetti.Security.Core.Tests;

public sealed class BecettiAiServiceTests
{
    private static BecettiAiService CreateAi(string apiUrl)
    {
        var dir = Path.Combine(Path.GetTempPath(), "becetti-test-" + Guid.NewGuid());
        var settings = new SettingsService(dir);
        settings.Current.AiApiBaseUrl = apiUrl;
        return new BecettiAiService(new HttpClient(), settings);
    }

    [Fact]
    public async Task SendAsync_NotConfigured_ReturnsNotConfiguredWithoutNetwork()
    {
        var ai = CreateAi(string.Empty);
        Assert.False(ai.IsConfigured);

        var result = await ai.SendAsync(new[] { new AiChatTurn { Role = "user", Content = "hello" } });

        Assert.False(result.Success);
        Assert.Equal("NOT_CONFIGURED", result.ErrorCode);
    }

    [Fact]
    public async Task SendAsync_EmptyHistory_RejectedWithoutNetwork()
    {
        var ai = CreateAi("https://api.example.test");

        var result = await ai.SendAsync(Array.Empty<AiChatTurn>());

        Assert.False(result.Success);
        Assert.Equal("EMPTY_INPUT", result.ErrorCode);
    }

    [Fact]
    public async Task SendAsync_UnreachableHost_RetriesOnceThenReportsBothAttemptsFailed()
    {
        // Port 9 (discard) on loopback is closed: connection refused, a genuine, fast
        // OFFLINE failure — this exercises the real one-automatic-retry path end to end
        // (two real failed attempts, a real 2-second pause between them) rather than
        // asserting on mocked behavior.
        var ai = CreateAi("http://127.0.0.1:9");

        var result = await ai.SendAsync(new[] { new AiChatTurn { Role = "user", Content = "hello" } });

        Assert.False(result.Success);
        Assert.Equal("OFFLINE", result.ErrorCode);
        Assert.Contains("twice in a row", result.Message, StringComparison.OrdinalIgnoreCase);
    }
}
