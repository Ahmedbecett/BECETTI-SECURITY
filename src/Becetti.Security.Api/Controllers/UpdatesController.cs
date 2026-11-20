using Becetti.Security.Api.Data;
using Becetti.Security.Api.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;

namespace Becetti.Security.Api.Controllers;

[ApiController]
[Route("api/v1/updates")]
[Authorize]
[EnableRateLimiting("api")]
public sealed class UpdatesController : ControllerBase
{
    private readonly AppDbContext _db;

    public UpdatesController(AppDbContext db)
    {
        _db = db;
    }

    /// <summary>Compare the client's version with the latest published release.</summary>
    [HttpGet("check")]
    public async Task<ActionResult<UpdateCheckResponse>> Check(
        [FromQuery] string currentVersion,
        [FromQuery] string channel = "stable",
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(currentVersion))
            return BadRequest(new { error = "currentVersion is required." });

        var normalizedChannel = string.IsNullOrWhiteSpace(channel) ? "stable" : channel.Trim().ToLowerInvariant();

        var latest = await _db.ReleaseVersions
            .Where(r => r.Channel == normalizedChannel)
            .OrderByDescending(r => r.PublishedAt)
            .FirstOrDefaultAsync(ct);

        if (latest is null)
        {
            return new UpdateCheckResponse
            {
                CurrentVersion = currentVersion,
                LatestVersion = null,
                UpdateAvailable = false,
                Channel = normalizedChannel
            };
        }

        var updateAvailable = CompareVersions(latest.Version, currentVersion) > 0;

        return new UpdateCheckResponse
        {
            CurrentVersion = currentVersion,
            LatestVersion = latest.Version,
            UpdateAvailable = updateAvailable,
            Channel = normalizedChannel,
            ReleaseNotes = latest.ReleaseNotes,
            StoreUrl = latest.StoreUrl
        };
    }

    internal static int CompareVersions(string a, string b)
    {
        var partsA = ParseVersion(a);
        var partsB = ParseVersion(b);
        var length = Math.Max(partsA.Length, partsB.Length);

        for (var i = 0; i < length; i++)
        {
            var x = i < partsA.Length ? partsA[i] : 0;
            var y = i < partsB.Length ? partsB[i] : 0;
            if (x != y)
                return x.CompareTo(y);
        }

        return 0;
    }

    private static int[] ParseVersion(string version)
    {
        return version.Split('.')
            .Select(p => int.TryParse(p.Trim(), out var n) ? n : 0)
            .ToArray();
    }
}
