using Becetti.Security.Api.Models;
using Microsoft.AspNetCore.Mvc;

namespace Becetti.Security.Api.Controllers;

/// <summary>Unauthenticated liveness/readiness probe.</summary>
[ApiController]
[Route("health")]
public sealed class HealthController : ControllerBase
{
    [HttpGet]
    public ActionResult<HealthResponse> Get()
    {
        return new HealthResponse
        {
            Status = "ok",
            Version = "1.0.0",
            ServerTime = DateTimeOffset.UtcNow
        };
    }
}
