using System.Net;
using System.Text;
using Becetti.Security.Core.Services;

namespace Becetti.Security.Core.Tests;

public sealed class BecettiAiServiceTests
{
    private static BecettiAiService CreateAi(string apiUrl, HttpMessageHandler? handler = null)
    {
        var dir = Path.Combine(Path.GetTempPath(), "becetti-test-" + Guid.NewGuid());
        var settings = new SettingsService(dir);
        settings.Current.AiApiBaseUrl = apiUrl;
        var http = handler is null ? new HttpClient() : new HttpClient(handler);
        return new BecettiAiService(http, settings);
    }

    private sealed class SequenceHandler : HttpMessageHandler
    {
        private readonly Queue<Func<HttpRequestMessage, HttpResponseMessage>> _responses;
        public int CallCount { get; private set; }

        public SequenceHandler(params Func<HttpRequestMessage, HttpResponseMessage>[] responses)
        {
            _responses = new Queue<Func<HttpRequestMessage, HttpResponseMessage>>(responses);
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            CallCount++;
            return Task.FromResult(_responses.Dequeue()(request));
        }
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
    public void NormalizeTurns_MergesConsecutiveSameRoleTurnsAndDropsLeadingAssistant()
    {
        var normalized = BecettiAiService.NormalizeTurns(new[]
        {
            new AiChatTurn { Role = "assistant", Content = "orphan greeting" },
            new AiChatTurn { Role = "user", Content = "[Real device context] Defender on" },
            new AiChatTurn { Role = "user", Content = "Is my PC safe?" },
            new AiChatTurn { Role = "assistant", Content = "Yes." },
            new AiChatTurn { Role = "user", Content = "Thanks!" }
        });

        Assert.Equal(3, normalized.Count);
        Assert.Equal("user", normalized[0].Role);
        Assert.Contains("[Real device context]", normalized[0].Content);
        Assert.Contains("Is my PC safe?", normalized[0].Content);
        Assert.Equal("assistant", normalized[1].Role);
        Assert.Equal("user", normalized[2].Role);
    }

    [Fact]
    public async Task SendAsync_Transient503UpstreamBusy_RetriesOnceAndSucceeds()
    {
        var handler = new SequenceHandler(
            _ => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable)
            {
                Content = new StringContent("{\"error\":\"UPSTREAM_ERROR\",\"message\":\"Model experiencing high demand\"}", Encoding.UTF8, "application/json")
            },
            _ => new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{\"reply\":\"Your YARA scan is clean.\",\"model\":\"gemini-flash-lite-latest\"}", Encoding.UTF8, "application/json")
            });

        var ai = CreateAi("https://api.example.test", handler);
        var result = await ai.SendAsync(new[] { new AiChatTurn { Role = "user", Content = "Check status" } });

        Assert.True(result.Success, result.Message);
        Assert.Equal(2, handler.CallCount);
        Assert.Equal("Your YARA scan is clean.", result.Value!.Reply);
    }

    [Fact]
    public async Task SendAsync_ServerNotConfigured503_ReturnsNotConfiguredImmediatelyWithoutRetry()
    {
        var handler = new SequenceHandler(
            _ => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable)
            {
                Content = new StringContent("{\"error\":\"NOT_CONFIGURED\",\"message\":\"GEMINI_API_KEY missing\"}", Encoding.UTF8, "application/json")
            });

        var ai = CreateAi("https://api.example.test", handler);
        var result = await ai.SendAsync(new[] { new AiChatTurn { Role = "user", Content = "Hello" } });

        Assert.False(result.Success);
        Assert.Equal("NOT_CONFIGURED", result.ErrorCode);
        Assert.Equal(1, handler.CallCount);
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
