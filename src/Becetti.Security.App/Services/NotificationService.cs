using System.Net.Http.Json;
using Becetti.Security.Core.Services;
using Microsoft.Windows.AppNotifications;
using Microsoft.Windows.AppNotifications.Builder;

namespace Becetti.Security.App.Services;

/// <summary>
/// Sends real critical security alerts two ways, both opt-out rather than
/// invented: (1) a native Windows notification via the Windows App SDK
/// (the same notification surface Windows' own apps use — it appears in
/// the real Windows Notification Center), and (2) an optional HTTP POST to
/// a webhook URL the user supplies in Settings (e.g. a Slack/Discord/
/// generic incoming webhook), so an alert can reach another device or
/// channel. Every call here is guarded so a failure (no notification
/// permission, unreachable webhook, non-Windows host) never blocks or
/// crashes the real security action that triggered it.
/// </summary>
public sealed class NotificationService
{
    private static readonly HttpClient WebhookClient = new() { Timeout = TimeSpan.FromSeconds(10) };

    private readonly ISettingsService _settings;
    private bool _registered;

    public NotificationService(ISettingsService settings)
    {
        _settings = settings;
    }

    /// <summary>Call once at app startup, before any NotifyCriticalAsync call.</summary>
    public void Initialize()
    {
        if (_registered || !OperatingSystem.IsWindows())
            return;

        try
        {
            AppNotificationManager.Default.Register();
            _registered = true;
        }
        catch
        {
            // Notifications are a convenience layer on top of this app's real protection,
            // never a dependency of it — a registration failure (e.g. unsupported host,
            // missing notification permission) must not affect anything else.
        }
    }

    /// <summary>
    /// Raises a critical alert: a local Windows notification (if enabled) and a webhook
    /// POST (if a URL is configured). <paramref name="title"/>/<paramref name="message"/>
    /// must describe a real event that already happened — never a simulated one.
    /// </summary>
    public async Task NotifyCriticalAsync(string title, string message)
    {
        if (_settings.Current.CriticalAlertNotificationsEnabled)
            ShowLocalNotification(title, message);

        var webhookUrl = _settings.Current.CriticalAlertWebhookUrl;
        if (!string.IsNullOrWhiteSpace(webhookUrl) && Uri.TryCreate(webhookUrl, UriKind.Absolute, out var uri))
            await PostWebhookAsync(uri, title, message).ConfigureAwait(false);
    }

    private void ShowLocalNotification(string title, string message)
    {
        if (!OperatingSystem.IsWindows() || !_registered)
            return;

        try
        {
            var notification = new AppNotificationBuilder()
                .AddText(title)
                .AddText(message)
                .BuildNotification();

            AppNotificationManager.Default.Show(notification);
        }
        catch
        {
            // Best-effort — see Initialize().
        }
    }

    private static async Task PostWebhookAsync(Uri uri, string title, string message)
    {
        try
        {
            var payload = new
            {
                text = $"{title}: {message}", // Slack/Discord-compatible "text" field
                title,
                message,
                source = "BECETTI SECURITY",
                timestampUtc = DateTimeOffset.UtcNow
            };

            using var response = await WebhookClient.PostAsJsonAsync(uri, payload).ConfigureAwait(false);
            // The outcome is intentionally not surfaced to the user beyond this: a webhook
            // delivery failure must never be mistaken for the underlying security event
            // itself having failed.
        }
        catch
        {
            // Best-effort delivery only.
        }
    }
}
