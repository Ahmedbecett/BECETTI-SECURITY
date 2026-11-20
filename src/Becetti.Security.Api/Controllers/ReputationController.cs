using System.Security.Claims;
using Becetti.Security.Api.Data;
using Becetti.Security.Api.Models;
using Becetti.Security.Api.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;

namespace Becetti.Security.Api.Controllers;

[ApiController]
[Route("api/v1/reputation")]
[Authorize]
[EnableRateLimiting("api")]
public sealed class ReputationController : ControllerBase
{
    private static readonly TimeSpan CacheLifetime = TimeSpan.FromHours(24);

    private readonly AppDbContext _db;
    private readonly VirusTotalService _virusTotal;

    public ReputationController(AppDbContext db, VirusTotalService virusTotal)
    {
        _db = db;
        _virusTotal = virusTotal;
    }

    /// <summary>
    /// Real reputation lookup: BECETTI database cache first, then the
    /// configured provider (VirusTotal). When no provider is configured the
    /// honest answer is "unknown" with source "no-provider-configured".
    /// </summary>
    [HttpPost("check")]
    public async Task<ActionResult<ReputationResponse>> Check([FromBody] ReputationCheckRequest request, CancellationToken ct)
    {
        if (!ModelState.IsValid)
            return ValidationProblem(ModelState);

        var sha256 = request.Sha256.ToLowerInvariant();
        var now = DateTimeOffset.UtcNow;

        var cached = await _db.ReputationEntries.FirstOrDefaultAsync(e => e.Sha256 == sha256, ct);
        if (cached is not null && now - cached.LastCheckedAt < CacheLifetime)
        {
            cached.TimesSeen++;
            await _db.SaveChangesAsync(ct);
            return Ok(ToResponse(cached));
        }

        ProviderVerdict verdict;
        var providerResult = await _virusTotal.CheckAsync(sha256, ct);
        if (providerResult is not null)
        {
            verdict = providerResult;
        }
        else
        {
            verdict = new ProviderVerdict(
                "unknown",
                "no-provider-configured",
                "No reputation provider is configured on the server (VirusTotal API key missing). The hash was not judged.");
        }

        if (cached is null)
        {
            cached = new ReputationEntry
            {
                Sha256 = sha256,
                Verdict = verdict.Verdict,
                Source = verdict.Source,
                Detail = verdict.Detail,
                FirstSeenAt = now,
                LastCheckedAt = now,
                TimesSeen = 1
            };
            _db.ReputationEntries.Add(cached);
        }
        else
        {
            cached.Verdict = verdict.Verdict;
            cached.Source = verdict.Source;
            cached.Detail = verdict.Detail;
            cached.LastCheckedAt = now;
            cached.TimesSeen++;
        }

        await _db.SaveChangesAsync(ct);
        await AuditAsync("reputation.check", $"{sha256} -> {verdict.Verdict} ({verdict.Source})", ct);

        return Ok(ToResponse(cached));
    }

    private static ReputationResponse ToResponse(ReputationEntry entry) => new()
    {
        Sha256 = entry.Sha256,
        Verdict = entry.Verdict,
        Source = entry.Source,
        Detail = entry.Detail,
        CheckedAt = entry.LastCheckedAt
    };

    private async Task AuditAsync(string action, string? detail, CancellationToken ct)
    {
        var sub = User.FindFirstValue(ClaimTypes.NameIdentifier) ?? User.FindFirstValue("sub");
        _db.AuditLogs.Add(new AuditLog
        {
            UserId = Guid.TryParse(sub, out var id) ? id : null,
            Action = action,
            Detail = detail,
            IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString()
        });
        await _db.SaveChangesAsync(ct);
    }
}
