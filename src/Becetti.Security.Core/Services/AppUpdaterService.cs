using System.Reflection;
using System.Text.Json;
using System.Text.RegularExpressions;
using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

public interface IAppUpdaterService
{
    string GetCurrentVersion();
    Task<OperationResult<AppReleaseInfo>> CheckLatestGitHubReleaseAsync(CancellationToken ct = default);
}

/// <summary>
/// Real In-App Auto-Updater backed by official GitHub Releases API
/// (Ahmedbecett/BECETTI-SECURITY): inspects latest published MSIX release tag,
/// compares semantic/build version against the installed app, and extracts
/// changelog + direct signed MSIX download URL. Zero simulation.
/// </summary>
public sealed class AppUpdaterService : IAppUpdaterService
{
    // Ask for the newest releases in one page (max page size GitHub allows) and then pick
    // the NUMERICALLY highest MSIX version ourselves. Do not trust the JSON order: every
    // CI build is created with the same release timestamp and is published with
    // --latest=false, so /releases/latest stays pinned to an old build and GitHub's list
    // ordering is not by version. Taking the first entry made the updater compare against
    // 1.0.0.63 while 1.0.0.97 was already published, i.e. it reported "up to date" to a
    // user running an older build - or worse, offered a downgrade.
    private const string ReleasesApiUrl = "https://api.github.com/repos/Ahmedbecett/BECETTI-SECURITY/releases?per_page=100";
    private static readonly Regex MsixVersionRegex = new("BECETTI-SECURITY_(\\d+\\.\\d+\\.\\d+\\.\\d+)_x64\\.msix", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private readonly HttpClient _http;

    public AppUpdaterService(HttpClient http)
    {
        _http = http;
    }

    public string GetCurrentVersion()
    {
        var entry = Assembly.GetEntryAssembly();
        var useEntry = entry?.GetName().Name?.StartsWith("Becetti.Security", StringComparison.OrdinalIgnoreCase) == true;
        var v = (useEntry ? entry!.GetName().Version : null)
                ?? typeof(AppUpdaterService).Assembly.GetName().Version;
        return v is null ? "1.0.0.0" : $"{v.Major}.{v.Minor}.{v.Build}.{Math.Max(0, v.Revision)}";
    }

    public async Task<OperationResult<AppReleaseInfo>> CheckLatestGitHubReleaseAsync(CancellationToken ct = default)
    {
        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, ReleasesApiUrl);
            req.Headers.TryAddWithoutValidation("User-Agent", "BECETTI-SECURITY-Updater/1.0");
            req.Headers.TryAddWithoutValidation("Accept", "application/vnd.github+json");

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(12));

            using var resp = await _http.SendAsync(req, cts.Token).ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode)
                return OperationResult<AppReleaseInfo>.Fail($"GitHub Releases API returned HTTP {(int)resp.StatusCode}.", "GITHUB_HTTP_ERROR");

            var body = await resp.Content.ReadAsStringAsync(cts.Token).ConfigureAwait(false);
            var currentVer = GetCurrentVersion();
            var info = ParseLatestReleaseJson(body, currentVer);
            if (info is null)
                return OperationResult<AppReleaseInfo>.Fail("No published Windows x64 MSIX release found yet.", "NO_RELEASES");

            var msg = info.IsUpdateAvailable
                ? $"Update available: v{info.LatestVersion} ({info.LatestTag}) — current v{info.CurrentVersion}."
                : $"You are running the latest release (v{info.LatestVersion} · {info.LatestTag}).";

            return OperationResult<AppReleaseInfo>.Ok(info, msg);
        }
        catch (Exception ex)
        {
            return OperationResult<AppReleaseInfo>.Fail($"Update check failed: {ex.Message}", "UPDATE_CHECK_ERROR");
        }
    }

    internal static AppReleaseInfo? ParseLatestReleaseJson(string releasesJson, string currentVersion)
    {
        using var doc = JsonDocument.Parse(releasesJson);
        if (doc.RootElement.ValueKind != JsonValueKind.Array)
            return null;

        // Pick the release/asset whose MSIX file name carries the highest version, so an
        // out-of-order JSON page can never make an older build look newest.
        string bestTag = string.Empty, bestHtmlUrl = string.Empty, bestNotes = string.Empty;
        string bestMsixUrl = string.Empty, bestMsixName = string.Empty, bestVersion = string.Empty;
        DateTimeOffset? bestPublished = null;

        foreach (var rel in doc.RootElement.EnumerateArray())
        {
            if (rel.TryGetProperty("draft", out var draftEl) && draftEl.ValueKind == JsonValueKind.True)
                continue;

            var tag = rel.TryGetProperty("tag_name", out var tEl) ? tEl.GetString() ?? "" : "";
            var htmlUrl = rel.TryGetProperty("html_url", out var hEl) ? hEl.GetString() ?? "" : "";
            var notes = rel.TryGetProperty("body", out var bEl) ? bEl.GetString() ?? "" : "";
            DateTimeOffset? pub = rel.TryGetProperty("published_at", out var pEl) && DateTimeOffset.TryParse(pEl.GetString(), out var parsedDate)
                ? parsedDate
                : null;

            if (!rel.TryGetProperty("assets", out var assetsEl) || assetsEl.ValueKind != JsonValueKind.Array)
                continue;

            foreach (var asset in assetsEl.EnumerateArray())
            {
                var name = asset.TryGetProperty("name", out var nEl) ? nEl.GetString() ?? "" : "";
                if (!name.EndsWith(".msix", StringComparison.OrdinalIgnoreCase))
                    continue;

                var url = asset.TryGetProperty("browser_download_url", out var uEl) ? uEl.GetString() ?? "" : "";
                if (string.IsNullOrWhiteSpace(url))
                    continue;

                var m = MsixVersionRegex.Match(name);
                var version = m.Success ? m.Groups[1].Value : ExtractVersionFromTag(tag);

                // File names that do not encode a version (legacy 1.0.0.0 test builds) still
                // compete, but on their tag-derived version, and never beat an equal one.
                if (string.IsNullOrEmpty(bestVersion) || CompareVersions(version, bestVersion) > 0)
                {
                    bestVersion = version;
                    bestMsixName = name;
                    bestMsixUrl = url;
                    bestTag = tag;
                    bestHtmlUrl = htmlUrl;
                    bestNotes = notes;
                    bestPublished = pub;
                }
                break; // only one .msix per release matters
            }
        }

        if (string.IsNullOrWhiteSpace(bestMsixUrl))
            return null;

        return new AppReleaseInfo
        {
            CurrentVersion = currentVersion,
            LatestTag = bestTag,
            LatestVersion = bestVersion,
            IsUpdateAvailable = CompareVersions(bestVersion, currentVersion) > 0,
            PublishedAt = bestPublished,
            ReleaseNotes = string.IsNullOrWhiteSpace(bestNotes) ? $"Signed Windows x64 MSIX release ({bestTag})." : bestNotes.Trim(),
            ReleasePageUrl = bestHtmlUrl,
            MsixDownloadUrl = bestMsixUrl,
            MsixFileName = bestMsixName
        };
    }

    internal static int CompareVersions(string a, string b)
    {
        if (Version.TryParse(NormalizeVersion(a), out var va) && Version.TryParse(NormalizeVersion(b), out var vb))
            return va.CompareTo(vb);
        return string.Compare(a, b, StringComparison.OrdinalIgnoreCase);
    }

    private static string NormalizeVersion(string v)
    {
        var clean = (v ?? "0.0.0.0").TrimStart('v', 'V').Split('-')[0];
        var parts = clean.Split('.');
        return parts.Length switch
        {
            1 => $"{parts[0]}.0.0.0",
            2 => $"{parts[0]}.{parts[1]}.0.0",
            3 => $"{parts[0]}.{parts[1]}.{parts[2]}.0",
            _ => clean
        };
    }

    private static string ExtractVersionFromTag(string tag)
    {
        var m = Regex.Match(tag ?? string.Empty, "(\\d+\\.\\d+(?:\\.\\d+)?(?:\\.\\d+)?)");
        return m.Success ? m.Groups[1].Value : "1.0.0.0";
    }
}
