using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

/// <summary>
/// HTTPS client for the BECETTI AI backend (a small server-side proxy that
/// holds the real Gemini key; see /backend/becetti-ai in the repo). This
/// class never talks to Gemini directly and never contains a key — only the
/// backend's own public URL, which is itself just a relay.
/// </summary>
public sealed class BecettiAiService : IBecettiAiService
{
    // Reduced from 45s: with one automatic retry below (see SendAsync), 45s per attempt
    // meant a genuinely unreachable server could take up to ~90 seconds to finally report
    // a failure. 30s is still generous for a gemini-2.5-flash reply (max 700 tokens).
    private static readonly TimeSpan RequestTimeout = TimeSpan.FromSeconds(30);

    private readonly HttpClient _http;
    private readonly ISettingsService _settings;

    public BecettiAiService(HttpClient http, ISettingsService settings)
    {
        _http = http;
        _settings = settings;
    }

    public bool IsConfigured => !string.IsNullOrWhiteSpace(_settings.Current.AiApiBaseUrl);

    private string BaseUrl => _settings.Current.AiApiBaseUrl.TrimEnd('/');

    public async Task<OperationResult<string>> SendAsync(IReadOnlyList<AiChatTurn> history, CancellationToken ct = default)
    {
        if (!IsConfigured)
        {
            return OperationResult<string>.Fail(
                "BECETTI AI is not configured. Open Settings and set the BECETTI AI server URL.",
                "NOT_CONFIGURED");
        }

        if (history.Count == 0)
            return OperationResult<string>.Fail("No message to send.", "EMPTY_INPUT");

        // Real-device testing showed this exact request timing out on a machine where a
        // normal browser reached the internet fine — a classic symptom of a one-off dropped
        // handshake (a restrictive firewall/antivirus, or a momentary flaky connection)
        // rather than the service genuinely being unreachable. One automatic retry of the
        // same real request rides out that kind of transient blip without ever fabricating
        // a result; if the second real attempt also fails, the real failure is reported.
        var first = await SendOnceAsync(history, ct).ConfigureAwait(false);
        if (first.Success || !IsTransientError(first.ErrorCode) || ct.IsCancellationRequested)
            return first;

        try
        {
            await Task.Delay(TimeSpan.FromSeconds(2), ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return first;
        }

        var second = await SendOnceAsync(history, ct).ConfigureAwait(false);
        if (second.Success)
            return second;

        var extraHint = second.ErrorCode is "TIMEOUT" or "OFFLINE"
            ? " This happened twice in a row (BECETTI SECURITY already retried automatically). If your internet otherwise works fine, check that your firewall or antivirus is not blocking BECETTI SECURITY from reaching the internet."
            : " (BECETTI SECURITY already retried automatically — please try again in a few seconds.)";

        return OperationResult<string>.Fail(second.Message + extraHint, second.ErrorCode);
    }

    private static bool IsTransientError(string? code) =>
        code is "TIMEOUT" or "OFFLINE" or "UPSTREAM_BUSY";

    private async Task<OperationResult<string>> SendOnceAsync(IReadOnlyList<AiChatTurn> history, CancellationToken ct)
    {
        using var timeoutCts = new CancellationTokenSource(RequestTimeout);
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct, timeoutCts.Token);

        try
        {
            var normalized = NormalizeTurns(history);
            var payload = new
            {
                messages = normalized.Select(h => new { role = h.Role, content = h.Content }).ToArray()
            };

            using var request = new HttpRequestMessage(HttpMethod.Post, BaseUrl + "/api/chat")
            {
                Content = JsonContent.Create(payload)
            };
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            using var response = await _http.SendAsync(request, linkedCts.Token).ConfigureAwait(false);
            var responseBody = await response.Content.ReadAsStringAsync(linkedCts.Token).ConfigureAwait(false);

            if (response.StatusCode == HttpStatusCode.ServiceUnavailable)
            {
                var errDto = TryReadErrorDto(responseBody);
                if (string.Equals(errDto?.Error, "NOT_CONFIGURED", StringComparison.OrdinalIgnoreCase))
                    return OperationResult<string>.Fail("BECETTI AI's server is not configured yet (no AI key set up).", "NOT_CONFIGURED");

                return OperationResult<string>.Fail(
                    errDto?.Message ?? "BECETTI AI is temporarily busy (HTTP 503).",
                    "UPSTREAM_BUSY");
            }

            if (response.StatusCode == HttpStatusCode.BadGateway)
            {
                var errDto = TryReadErrorDto(responseBody);
                return OperationResult<string>.Fail(
                    errDto?.Message ?? "BECETTI AI upstream model is temporarily unavailable (HTTP 502).",
                    "UPSTREAM_BUSY");
            }

            if (response.StatusCode == HttpStatusCode.TooManyRequests)
                return OperationResult<string>.Fail("Too many requests. Wait a moment and try again.", "RATE_LIMITED");

            if (!response.IsSuccessStatusCode)
            {
                var errorMessage = TryReadErrorDto(responseBody)?.Message ?? $"Server returned {(int)response.StatusCode} {response.StatusCode}.";
                return OperationResult<string>.Fail(errorMessage, "SERVER_ERROR");
            }

            if (string.IsNullOrWhiteSpace(responseBody))
                return OperationResult<string>.Fail("The server returned an empty response.", "EMPTY_RESPONSE");

            var parsed = JsonSerializer.Deserialize<ChatResponseDto>(responseBody, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            if (parsed is null || string.IsNullOrWhiteSpace(parsed.Reply))
                return OperationResult<string>.Fail("The server returned no reply.", "EMPTY_REPLY");

            return OperationResult<string>.Ok(parsed.Reply);
        }
        catch (OperationCanceledException)
        {
            return OperationResult<string>.Fail("The request to BECETTI AI timed out. Check your internet connection.", "TIMEOUT");
        }
        catch (HttpRequestException ex)
        {
            return OperationResult<string>.Fail($"Could not reach BECETTI AI: {ex.Message}", "OFFLINE");
        }
        catch (Exception ex)
        {
            return OperationResult<string>.Fail($"BECETTI AI request failed: {ex.Message}", "AI_ERROR");
        }
    }

    internal static IReadOnlyList<AiChatTurn> NormalizeTurns(IReadOnlyList<AiChatTurn> history)
    {
        var result = new List<AiChatTurn>();
        foreach (var turn in history)
        {
            if (string.IsNullOrWhiteSpace(turn.Content))
                continue;

            var role = string.Equals(turn.Role, "assistant", StringComparison.OrdinalIgnoreCase)
                ? "assistant"
                : "user";

            if (result.Count > 0 && string.Equals(result[^1].Role, role, StringComparison.Ordinal))
            {
                result[^1] = new AiChatTurn
                {
                    Role = role,
                    Content = result[^1].Content + "\n\n" + turn.Content
                };
            }
            else
            {
                result.Add(new AiChatTurn { Role = role, Content = turn.Content });
            }
        }

        // Gemini expects conversation history to begin with a user turn.
        while (result.Count > 0 && !string.Equals(result[0].Role, "user", StringComparison.Ordinal))
            result.RemoveAt(0);

        return result;
    }

    private static ErrorDto? TryReadErrorDto(string body)
    {
        try
        {
            return JsonSerializer.Deserialize<ErrorDto>(body, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        }
        catch
        {
            return null;
        }
    }

    private sealed class ChatResponseDto
    {
        [JsonPropertyName("reply")] public string Reply { get; set; } = string.Empty;
        [JsonPropertyName("model")] public string? Model { get; set; }
    }

    private sealed class ErrorDto
    {
        [JsonPropertyName("error")] public string? Error { get; set; }
        [JsonPropertyName("message")] public string? Message { get; set; }
    }
}
