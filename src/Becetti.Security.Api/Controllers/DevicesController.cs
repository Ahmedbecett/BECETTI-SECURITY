using System.Security.Claims;
using Becetti.Security.Api.Data;
using Becetti.Security.Api.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;

namespace Becetti.Security.Api.Controllers;

/// <summary>
/// Multi-device dashboard: lets a signed-in user see every real device that
/// has checked in under their account (name, platform, app version, last
/// seen) and remove one that is lost or no longer in use. Every row here
/// reflects an actual heartbeat the app itself sent — nothing is invented.
/// </summary>
[ApiController]
[Route("api/v1/devices")]
[Authorize]
[EnableRateLimiting("api")]
public sealed class DevicesController : ControllerBase
{
    private readonly AppDbContext _db;

    public DevicesController(AppDbContext db)
    {
        _db = db;
    }

    /// <summary>
    /// Records (or updates) a real check-in for the calling device. Called
    /// by the app itself on startup and periodically while signed in — never
    /// fabricated server-side.
    /// </summary>
    [HttpPost("heartbeat")]
    public async Task<ActionResult<DeviceResponse>> Heartbeat([FromBody] DeviceHeartbeatRequest request, CancellationToken ct)
    {
        if (!ModelState.IsValid)
            return ValidationProblem(ModelState);

        var userId = GetCurrentUserId();
        if (!userId.HasValue)
            return Unauthorized();

        var now = DateTimeOffset.UtcNow;
        var device = await _db.Devices.FirstOrDefaultAsync(
            d => d.UserId == userId.Value && d.DeviceId == request.DeviceId, ct);

        if (device is null)
        {
            device = new Device
            {
                UserId = userId.Value,
                DeviceId = request.DeviceId,
                DeviceName = request.DeviceName,
                Platform = request.Platform,
                AppVersion = request.AppVersion,
                FirstSeenAt = now,
                LastSeenAt = now
            };
            _db.Devices.Add(device);
            await AuditAsync(userId.Value, "devices.register", $"{request.DeviceName} ({request.Platform})", ct);
        }
        else
        {
            device.DeviceName = request.DeviceName;
            device.Platform = request.Platform;
            device.AppVersion = request.AppVersion;
            device.LastSeenAt = now;
        }

        await _db.SaveChangesAsync(ct);
        return Ok(ToResponse(device));
    }

    /// <summary>Lists every device registered under the calling user's account, most recently seen first.</summary>
    [HttpGet]
    public async Task<ActionResult<List<DeviceResponse>>> List(CancellationToken ct)
    {
        var userId = GetCurrentUserId();
        if (!userId.HasValue)
            return Unauthorized();

        var devices = await _db.Devices
            .Where(d => d.UserId == userId.Value)
            .OrderByDescending(d => d.LastSeenAt)
            .ToListAsync(ct);

        return devices.Select(ToResponse).ToList();
    }

    /// <summary>Removes a device from the account's dashboard (e.g. a lost or retired machine). It will reappear if that device ever sends another heartbeat.</summary>
    [HttpDelete("{deviceId}")]
    public async Task<IActionResult> Remove(string deviceId, CancellationToken ct)
    {
        var userId = GetCurrentUserId();
        if (!userId.HasValue)
            return Unauthorized();

        var device = await _db.Devices.FirstOrDefaultAsync(
            d => d.UserId == userId.Value && d.DeviceId == deviceId, ct);
        if (device is null)
            return NotFound();

        _db.Devices.Remove(device);
        await _db.SaveChangesAsync(ct);
        await AuditAsync(userId.Value, "devices.remove", $"{device.DeviceName} ({device.Platform})", ct);
        return NoContent();
    }

    private static DeviceResponse ToResponse(Device device) => new()
    {
        DeviceId = device.DeviceId,
        DeviceName = device.DeviceName,
        Platform = device.Platform,
        AppVersion = device.AppVersion,
        FirstSeenAt = device.FirstSeenAt,
        LastSeenAt = device.LastSeenAt
    };

    private Guid? GetCurrentUserId()
    {
        var sub = User.FindFirstValue(ClaimTypes.NameIdentifier) ?? User.FindFirstValue("sub");
        return Guid.TryParse(sub, out var id) ? id : null;
    }

    private async Task AuditAsync(Guid userId, string action, string? detail, CancellationToken ct)
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
