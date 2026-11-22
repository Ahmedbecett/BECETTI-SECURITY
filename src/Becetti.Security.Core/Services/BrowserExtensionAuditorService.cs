using System.Text.Json;
using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

public interface IBrowserExtensionAuditorService
{
    Task<OperationResult<BrowserExtensionAuditReport>> AuditAsync(CancellationToken ct = default);
}

/// <summary>
/// Real local Browser Extensions Risk Auditor: inspects installed Chrome, Microsoft Edge,
/// Brave, and Firefox browser profiles on disk, parses real manifest.json / extensions.json
/// metadata &amp; requested permissions, and flags high-privilege extensions. Zero simulation.
/// </summary>
public sealed class BrowserExtensionAuditorService : IBrowserExtensionAuditorService
{
    private static readonly Dictionary<string, (int Weight, string Note)> DangerousPermissions = new(StringComparer.OrdinalIgnoreCase)
    {
        ["<all_urls>"] = (4, "Full read/write access on EVERY website"),
        ["*://*/*"] = (4, "Full read/write access on all HTTP/HTTPS sites"),
        ["http://*/*"] = (3, "Access to all HTTP websites"),
        ["https://*/*"] = (3, "Access to all HTTPS websites"),
        ["debugger"] = (4, "Can attach Chrome DevTools debugger to tabs"),
        ["nativeMessaging"] = (4, "Can launch/communicate with native OS binaries"),
        ["webRequestBlocking"] = (3, "Can intercept and modify live web requests"),
        ["webRequest"] = (2, "Can observe all live network traffic in browser"),
        ["cookies"] = (3, "Can read and export authentication session cookies"),
        ["proxy"] = (3, "Can reroute all browser traffic through external proxies"),
        ["management"] = (3, "Can inspect, enable, or disable other extensions"),
        ["clipboardRead"] = (2, "Can read system clipboard contents"),
        ["tabs"] = (1, "Can read URLs and titles of open browser tabs"),
        ["history"] = (2, "Can read full browsing history"),
        ["downloads"] = (2, "Can initiate or inspect file downloads"),
        ["scripting"] = (2, "Can inject arbitrary scripts into web pages")
    };

    public async Task<OperationResult<BrowserExtensionAuditReport>> AuditAsync(CancellationToken ct = default)
    {
        var items = new List<BrowserExtensionItem>();
        int browsersFound = 0;

        await Task.Run(() =>
        {
            var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

            var chromiumRoots = new (string Browser, string UserDataPath)[]
            {
                ("Google Chrome", Path.Combine(localAppData, "Google", "Chrome", "User Data")),
                ("Microsoft Edge", Path.Combine(localAppData, "Microsoft", "Edge", "User Data")),
                ("Brave", Path.Combine(localAppData, "BraveSoftware", "Brave-Browser", "User Data"))
            };

            foreach (var (browser, root) in chromiumRoots)
            {
                ct.ThrowIfCancellationRequested();
                if (!Directory.Exists(root))
                    continue;
                browsersFound++;
                InspectChromiumBrowser(browser, root, items, ct);
            }

            var firefoxProfiles = Path.Combine(appData, "Mozilla", "Firefox", "Profiles");
            if (Directory.Exists(firefoxProfiles))
            {
                browsersFound++;
                InspectFirefoxProfiles(firefoxProfiles, items, ct);
            }
        }, ct).ConfigureAwait(false);

        var ordered = items
            .OrderByDescending(i => RiskWeight(i.RiskLevel))
            .ThenBy(i => i.Browser, StringComparer.OrdinalIgnoreCase)
            .ThenBy(i => i.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var report = new BrowserExtensionAuditReport
        {
            AuditedAt = DateTimeOffset.UtcNow,
            TotalExtensions = ordered.Count,
            HighRiskCount = ordered.Count(e => e.RiskLevel is "High" or "Critical"),
            BrowsersInspected = browsersFound,
            Extensions = ordered
        };

        return OperationResult<BrowserExtensionAuditReport>.Ok(
            report,
            $"Audited {ordered.Count} browser extension(s) across {browsersFound} browser(s) ({report.HighRiskCount} high-risk).");
    }

    private static void InspectChromiumBrowser(string browser, string userDataRoot, List<BrowserExtensionItem> output, CancellationToken ct)
    {
        IEnumerable<string> profileDirs;
        try
        {
            profileDirs = Directory.EnumerateDirectories(userDataRoot)
                .Where(d =>
                {
                    var name = Path.GetFileName(d);
                    return name.Equals("Default", StringComparison.OrdinalIgnoreCase) ||
                           name.StartsWith("Profile ", StringComparison.OrdinalIgnoreCase);
                });
        }
        catch
        {
            return;
        }

        foreach (var profileDir in profileDirs)
        {
            ct.ThrowIfCancellationRequested();
            var profileName = Path.GetFileName(profileDir);
            var extRoot = Path.Combine(profileDir, "Extensions");
            if (!Directory.Exists(extRoot))
                continue;

            IEnumerable<string> extIdDirs;
            try { extIdDirs = Directory.EnumerateDirectories(extRoot); }
            catch { continue; }

            foreach (var extIdDir in extIdDirs)
            {
                ct.ThrowIfCancellationRequested();
                var extId = Path.GetFileName(extIdDir);
                string? latestVersionDir = null;
                try
                {
                    latestVersionDir = Directory.EnumerateDirectories(extIdDir)
                        .OrderByDescending(Path.GetFileName, StringComparer.OrdinalIgnoreCase)
                        .FirstOrDefault();
                }
                catch { continue; }

                if (string.IsNullOrWhiteSpace(latestVersionDir))
                    continue;

                var manifestPath = Path.Combine(latestVersionDir, "manifest.json");
                if (!File.Exists(manifestPath))
                    continue;

                var parsed = ParseChromiumManifest(browser, profileName, extId, manifestPath);
                if (parsed is not null)
                    output.Add(parsed);
            }
        }
    }

    internal static BrowserExtensionItem? ParseChromiumManifest(string browser, string profile, string extId, string manifestPath)
    {
        try
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(manifestPath));
            var root = doc.RootElement;

            var rawName = root.TryGetProperty("name", out var nEl) && nEl.ValueKind == JsonValueKind.String
                ? nEl.GetString() ?? extId
                : extId;

            var name = ResolveLocalizedManifestString(rawName, Path.GetDirectoryName(manifestPath)!);
            var version = root.TryGetProperty("version", out var vEl) && vEl.ValueKind == JsonValueKind.String
                ? vEl.GetString() ?? "0.0"
                : "0.0";

            var perms = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            ExtractStringArray(root, "permissions", perms);
            ExtractStringArray(root, "host_permissions", perms);
            ExtractStringArray(root, "optional_permissions", perms);

            if (root.TryGetProperty("content_scripts", out var cs) && cs.ValueKind == JsonValueKind.Array)
            {
                foreach (var script in cs.EnumerateArray())
                    ExtractStringArray(script, "matches", perms);
            }

            return BuildScoredItem(browser, profile, extId, name, version, manifestPath, perms.ToList());
        }
        catch
        {
            return null;
        }
    }

    private static void InspectFirefoxProfiles(string profilesRoot, List<BrowserExtensionItem> output, CancellationToken ct)
    {
        IEnumerable<string> profileDirs;
        try { profileDirs = Directory.EnumerateDirectories(profilesRoot); }
        catch { return; }

        foreach (var profileDir in profileDirs)
        {
            ct.ThrowIfCancellationRequested();
            var extJsonPath = Path.Combine(profileDir, "extensions.json");
            if (!File.Exists(extJsonPath))
                continue;

            try
            {
                using var doc = JsonDocument.Parse(File.ReadAllText(extJsonPath));
                if (!doc.RootElement.TryGetProperty("addons", out var addons) || addons.ValueKind != JsonValueKind.Array)
                    continue;

                var profileName = Path.GetFileName(profileDir);
                foreach (var addon in addons.EnumerateArray())
                {
                    var type = addon.TryGetProperty("type", out var tEl) ? tEl.GetString() : null;
                    if (!string.Equals(type, "extension", StringComparison.OrdinalIgnoreCase))
                        continue;

                    var location = addon.TryGetProperty("location", out var lEl) ? lEl.GetString() : null;
                    if (string.Equals(location, "app-builtin", StringComparison.OrdinalIgnoreCase))
                        continue;

                    var id = addon.TryGetProperty("id", out var idEl) ? idEl.GetString() ?? "unknown" : "unknown";
                    var version = addon.TryGetProperty("version", out var vEl) ? vEl.GetString() ?? "0.0" : "0.0";
                    var name = id;
                    if (addon.TryGetProperty("defaultLocale", out var loc) && loc.ValueKind == JsonValueKind.Object &&
                        loc.TryGetProperty("name", out var nEl) && nEl.ValueKind == JsonValueKind.String)
                    {
                        name = nEl.GetString() ?? id;
                    }

                    var perms = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    if (addon.TryGetProperty("userPermissions", out var up) && up.ValueKind == JsonValueKind.Object)
                    {
                        ExtractStringArray(up, "permissions", perms);
                        ExtractStringArray(up, "origins", perms);
                    }

                    output.Add(BuildScoredItem("Mozilla Firefox", profileName, id, name, version, extJsonPath, perms.ToList()));
                }
            }
            catch
            {
                // Skip unreadable profile JSON
            }
        }
    }

    internal static BrowserExtensionItem BuildScoredItem(
        string browser,
        string profile,
        string extId,
        string name,
        string version,
        string manifestPath,
        IReadOnlyList<string> permissions)
    {
        int totalWeight = 0;
        var risky = new List<string>();
        var notes = new List<string>();

        foreach (var p in permissions)
        {
            if (DangerousPermissions.TryGetValue(p, out var info))
            {
                totalWeight += info.Weight;
                risky.Add(p);
                if (notes.Count < 3)
                    notes.Add($"{p} ({info.Note})");
            }
            else if (p.StartsWith("http://*", StringComparison.OrdinalIgnoreCase) ||
                     p.StartsWith("https://*", StringComparison.OrdinalIgnoreCase) ||
                     p.Contains("://*/*", StringComparison.OrdinalIgnoreCase))
            {
                totalWeight += 3;
                risky.Add(p);
            }
        }

        string riskLevel = totalWeight switch
        {
            >= 9 => "Critical",
            >= 5 => "High",
            >= 2 => "Medium",
            _ => "Low"
        };

        string summary = notes.Count > 0
            ? string.Join("; ", notes)
            : permissions.Count == 0
                ? "No sensitive permissions requested."
                : $"Standard permissions ({permissions.Count}).";

        return new BrowserExtensionItem
        {
            Browser = browser,
            Profile = profile,
            ExtensionId = extId,
            Name = name,
            Version = version,
            ManifestPath = manifestPath,
            Permissions = permissions,
            RiskyPermissions = risky,
            RiskLevel = riskLevel,
            RiskSummary = summary
        };
    }

    private static string ResolveLocalizedManifestString(string raw, string extensionDir)
    {
        if (!raw.StartsWith("__MSG_", StringComparison.Ordinal) || !raw.EndsWith("__", StringComparison.Ordinal))
            return raw;

        var key = raw[6..^2];
        string[] candidateLocales = { "en", "en_US", "en_GB" };
        foreach (var loc in candidateLocales)
        {
            var msgPath = Path.Combine(extensionDir, "_locales", loc, "messages.json");
            if (!File.Exists(msgPath))
                continue;
            try
            {
                using var doc = JsonDocument.Parse(File.ReadAllText(msgPath));
                foreach (var prop in doc.RootElement.EnumerateObject())
                {
                    if (prop.Name.Equals(key, StringComparison.OrdinalIgnoreCase) &&
                        prop.Value.TryGetProperty("message", out var msgEl) &&
                        msgEl.ValueKind == JsonValueKind.String)
                    {
                        return msgEl.GetString() ?? raw;
                    }
                }
            }
            catch { }
        }
        return raw;
    }

    private static void ExtractStringArray(JsonElement parent, string propertyName, HashSet<string> target)
    {
        if (!parent.TryGetProperty(propertyName, out var arr) || arr.ValueKind != JsonValueKind.Array)
            return;
        foreach (var el in arr.EnumerateArray())
        {
            if (el.ValueKind == JsonValueKind.String)
            {
                var val = el.GetString();
                if (!string.IsNullOrWhiteSpace(val))
                    target.Add(val);
            }
        }
    }

    private static int RiskWeight(string level) => level switch
    {
        "Critical" => 4,
        "High" => 3,
        "Medium" => 2,
        _ => 1
    };
}
