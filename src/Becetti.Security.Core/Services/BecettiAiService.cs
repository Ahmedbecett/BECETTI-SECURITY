using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

/// <summary>
/// HTTPS client for the BECETTI AI backend (a small server-side proxy that
/// holds the real OpenAI key; see /backend/becetti-ai in the repo). This
/// class never talks to OpenAI directly and never contains a key — only the
/// backend's own public URL, which is itself just a relay.
/// </summary>
public sealed class BecettiAiService : IBecettiAiService
{
    private static readonly TimeSpan RequestTimeout = TimeSpan.FromSeconds(45);

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

        using var timeoutCts = new CancellationTokenSource(RequestTimeout);
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct, timeoutCts.Token);

        try
        {
            var payload = new
            {
                messages = history.Select(h => new { role = h.Role, content = h.Content }).ToArray()
            };

            using var request = new HttpRequestMessage(HttpMethod.Post, BaseUrl + "/api/chat")
            {
                Content = JsonContent.Create(payload)
            };
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            using var response = await _http.SendAsync(request, linkedCts.Token).ConfigureAwait(false);
            var responseBody = await response.Content.ReadAsStringAsync(linkedCts.Token).ConfigureAwait(false);

            if (response.StatusCode == HttpStatusCode.ServiceUnavailable)
                return OperationResult<string>.Fail("BECETTI AI's server is not configured yet (no AI key set up).", "NOT_CONFIGURED");

            if (response.StatusCode == HttpStatusCode.TooManyRequests)
                return OperationResult<string>.Fail("Too many requests. Wait a moment and try again.", "RATE_LIMITED");

            if (!response.IsSuccessStatusCode)
            {
                var errorMessage = TryReadErrorMessage(responseBody) ?? $"Server returned {(int)response.StatusCode} {response.StatusCode}.";
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

    private static string? TryReadErrorMessage(string body)
    {
        try
        {
            var dto = JsonSerializer.Deserialize<ErrorDto>(body, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            return dto?.Message;
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
