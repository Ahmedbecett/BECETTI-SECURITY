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
[Route("api/v1/auth")]
[EnableRateLimiting("auth")]
public sealed class AuthController : ControllerBase
{
    private readonly AppDbContext _db;
    private readonly TokenService _tokens;
    private readonly PasswordService _passwords;
    private readonly IConfiguration _configuration;

    public AuthController(AppDbContext db, TokenService tokens, PasswordService passwords, IConfiguration configuration)
    {
        _db = db;
        _tokens = tokens;
        _passwords = passwords;
        _configuration = configuration;
    }

    [HttpPost("register")]
    public async Task<ActionResult<TokenResponse>> Register([FromBody] RegisterRequest request, CancellationToken ct)
    {
        if (!ModelState.IsValid)
            return ValidationProblem(ModelState);

        var email = request.Email.Trim().ToLowerInvariant();
        if (await _db.Users.AnyAsync(u => u.Email == email, ct))
            return Conflict(new { error = "An account with this email already exists." });

        var user = new User
        {
            Email = email,
            PasswordHash = _passwords.Hash(request.Password)
        };
        _db.Users.Add(user);
        await _db.SaveChangesAsync(ct);

        await AuditAsync(user.Id, "auth.register", $"Registered {email}", ct);
        return Ok(await IssueTokensAsync(user, ct));
    }

    [HttpPost("login")]
    public async Task<ActionResult<TokenResponse>> Login([FromBody] LoginRequest request, CancellationToken ct)
    {
        if (!ModelState.IsValid)
            return ValidationProblem(ModelState);

        var email = request.Email.Trim().ToLowerInvariant();
        var user = await _db.Users.FirstOrDefaultAsync(u => u.Email == email, ct);

        // Same response whether the email exists or not (no account enumeration).
        if (user is null || !_passwords.Verify(request.Password, user.PasswordHash))
            return Unauthorized(new { error = "Invalid email or password." });

        await AuditAsync(user.Id, "auth.login", $"Signed in {email}", ct);
        return Ok(await IssueTokensAsync(user, ct));
    }

    [HttpPost("refresh")]
    public async Task<ActionResult<TokenResponse>> Refresh([FromBody] RefreshRequest request, CancellationToken ct)
    {
        if (!ModelState.IsValid)
            return ValidationProblem(ModelState);

        var hash = TokenService.HashToken(request.RefreshToken);
        var stored = await _db.RefreshTokens
            .Include(r => r.User)
            .FirstOrDefaultAsync(r => r.TokenHash == hash, ct);

        if (stored is null || stored.RevokedAt is not null || stored.ExpiresAt <= DateTimeOffset.UtcNow)
            return Unauthorized(new { error = "Refresh token is invalid or expired." });

        stored.RevokedAt = DateTimeOffset.UtcNow;
        await _db.SaveChangesAsync(ct);

        await AuditAsync(stored.UserId, "auth.refresh", "Session refreshed", ct);
        return Ok(await IssueTokensAsync(stored.User, ct));
    }

    [HttpPost("logout")]
    [Authorize]
    public async Task<IActionResult> Logout([FromBody] RefreshRequest request, CancellationToken ct)
    {
        var hash = TokenService.HashToken(request.RefreshToken);
        var stored = await _db.RefreshTokens.FirstOrDefaultAsync(r => r.TokenHash == hash, ct);
        if (stored is not null)
        {
            stored.RevokedAt = DateTimeOffset.UtcNow;
            await _db.SaveChangesAsync(ct);
        }

        var userId = GetCurrentUserId();
        if (userId.HasValue)
            await AuditAsync(userId.Value, "auth.logout", "Signed out", ct);

        return NoContent();
    }

    [HttpGet("me")]
    [Authorize]
    public async Task<ActionResult<MeResponse>> Me(CancellationToken ct)
    {
        var userId = GetCurrentUserId();
        if (!userId.HasValue)
            return Unauthorized();

        var user = await _db.Users.FirstOrDefaultAsync(u => u.Id == userId.Value, ct);
        if (user is null)
            return Unauthorized();

        return new MeResponse { Email = user.Email, IsAdmin = user.IsAdmin };
    }

    private async Task<TokenResponse> IssueTokensAsync(User user, CancellationToken ct)
    {
        var (accessToken, expiresAt) = _tokens.CreateAccessToken(user);
        var refreshToken = _tokens.CreateRefreshToken();
        var refreshDays = int.TryParse(_configuration["Jwt:RefreshTokenDays"], out var days) && days > 0 ? days : 30;

        _db.RefreshTokens.Add(new RefreshToken
        {
            UserId = user.Id,
            TokenHash = TokenService.HashToken(refreshToken),
            ExpiresAt = DateTimeOffset.UtcNow.AddDays(refreshDays)
        });
        await _db.SaveChangesAsync(ct);

        return new TokenResponse
        {
            AccessToken = accessToken,
            RefreshToken = refreshToken,
            ExpiresAt = expiresAt
        };
    }

    private Guid? GetCurrentUserId()
    {
        var sub = User.FindFirstValue(ClaimTypes.NameIdentifier) ?? User.FindFirstValue("sub");
        return Guid.TryParse(sub, out var id) ? id : null;
    }

    private async Task AuditAsync(Guid? userId, string action, string? detail, CancellationToken ct)
    {
        _db.AuditLogs.Add(new AuditLog
        {
            UserId = userId,
            Action = action,
            Detail = detail,
            IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString()
        });
        await _db.SaveChangesAsync(ct);
    }
}
