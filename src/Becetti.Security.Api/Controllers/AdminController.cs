using Becetti.Security.Api.Data;
using Becetti.Security.Api.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;

namespace Becetti.Security.Api.Controllers;

/// <summary>Administrator-only operations: intel statistics, manual intel ingest, release publishing.</summary>
[ApiController]
[Route("api/v1/admin")]
[Authorize(Roles = "Admin")]
[EnableRateLimiting("api")]
public sealed class AdminController : ControllerBase
{
    private readonly AppDbContext _db;

    public AdminController(AppDbContext db)
    {
        _db = db;
    }

    [HttpGet("intel/stats")]
    public async Task<ActionResult<IntelStatsResponse>> Stats(CancellationToken ct)
    {
        return new IntelStatsResponse
        {
            TotalUsers = await _db.Users.CountAsync(ct),
            TotalReputationEntries = await _db.ReputationEntries.CountAsync(ct),
            MaliciousEntries = await _db.ReputationEntries.CountAsync(e => e.Verdict == "malicious", ct),
            TotalReleases = await _db.ReleaseVersions.CountAsync(ct),
            TotalAuditEvents = await _db.AuditLogs.CountAsync(ct)
        };
    }

    [HttpPost("reputation/ingest")]
    public async Task<ActionResult<ReputationResponse>> Ingest([FromBody] ReputationIngestRequest request, CancellationToken ct)
    {
        if (!ModelState.IsValid)
            return ValidationProblem(ModelState);

        var sha256 = request.Sha256.ToLowerInvariant();
        var now = DateTimeOffset.UtcNow;

        var existing = await _db.ReputationEntries.FirstOrDefaultAsync(e => e.Sha256 == sha256, ct);
        if (existing is null)
        {
            existing = new ReputationEntry
            {
                Sha256 = sha256,
                Verdict = request.Verdict,
                Source = request.Source,
                Detail = request.Detail,
                FirstSeenAt = now,
                LastCheckedAt = now,
                TimesSeen = 1
            };
            _db.ReputationEntries.Add(existing);
        }
        else
        {
            existing.Verdict = request.Verdict;
            existing.Source = request.Source;
            existing.Detail = request.Detail;
            existing.LastCheckedAt = now;
        }

        await _db.SaveChangesAsync(ct);
        await AuditAsync("admin.reputation.ingest", $"{sha256} -> {request.Verdict}", ct);

        return Ok(new ReputationResponse
        {
            Sha256 = existing.Sha256,
            Verdict = existing.Verdict,
            Source = existing.Source,
            Detail = existing.Detail,
            CheckedAt = existing.LastCheckedAt
        });
    }

    [HttpGet("releases")]
    public async Task<ActionResult<IReadOnlyList<ReleaseVersion>>> Releases(CancellationToken ct)
    {
        var releases = await _db.ReleaseVersions
            .OrderByDescending(r => r.PublishedAt)
            .ToListAsync(ct);
        return Ok(releases);
    }

    [HttpPost("releases")]
    public async Task<ActionResult<ReleaseVersion>> Publish([FromBody] ReleasePublishRequest request, CancellationToken ct)
    {
        if (!ModelState.IsValid)
            return ValidationProblem(ModelState);

        var channel = string.IsNullOrWhiteSpace(request.Channel) ? "stable" : request.Channel.Trim().ToLowerInvariant();
        var exists = await _db.ReleaseVersions.AnyAsync(r => r.Channel == channel && r.Version == request.Version, ct);
        if (exists)
            return Conflict(new { error = $"Version {request.Version} on channel {channel} already exists." });

        var release = new ReleaseVersion
        {
            Version = request.Version,
            Channel = channel,
            ReleaseNotes = request.ReleaseNotes,
            StoreUrl = request.StoreUrl,
            IsMandatory = request.IsMandatory,
            PublishedAt = DateTimeOffset.UtcNow
        };
        _db.ReleaseVersions.Add(release);
        await _db.SaveChangesAsync(ct);
        await AuditAsync("admin.release.publish", $"{channel} {request.Version}", ct);

        return CreatedAtAction(nameof(Releases), new { }, release);
    }

    private async Task AuditAsync(string action, string? detail, CancellationToken ct)
    {
        _db.AuditLogs.Add(new AuditLog
        {
            Action = action,
            Detail = detail,
            IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString()
        });
        await _db.SaveChangesAsync(ct);
    }
}
