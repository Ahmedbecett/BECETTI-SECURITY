using System.Text;
using Becetti.Security.Api.Data;
using Becetti.Security.Api.Models;
using Becetti.Security.Api.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Threading.RateLimiting;

var builder = WebApplication.CreateBuilder(args);

// ---------- Configuration ----------
// Secrets come from environment variables / secret manager, never from the repo:
//   ConnectionStrings__Postgres, Jwt__SigningKey, VirusTotal__ApiKey, AdminSeed__*
var connectionString = builder.Configuration.GetConnectionString("Postgres");
if (string.IsNullOrWhiteSpace(connectionString))
    throw new InvalidOperationException("ConnectionStrings:Postgres is not configured. Set it via environment variable ConnectionStrings__Postgres.");

var jwtKey = builder.Configuration["Jwt:SigningKey"];
if (string.IsNullOrWhiteSpace(jwtKey) || jwtKey.Length < 32)
    throw new InvalidOperationException("Jwt:SigningKey must be set via environment variable Jwt__SigningKey and be at least 32 characters long.");

// ---------- Services ----------
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();

builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseNpgsql(connectionString));

builder.Services.AddScoped<TokenService>();
builder.Services.AddScoped<PasswordService>();
builder.Services.AddHttpClient<VirusTotalService>(client =>
{
    client.Timeout = TimeSpan.FromSeconds(20);
});

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = builder.Configuration["Jwt:Issuer"] ?? "becetti-security-api",
            ValidAudience = builder.Configuration["Jwt:Audience"] ?? "becetti-security-app",
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey)),
            ClockSkew = TimeSpan.FromMinutes(1)
        };
    });

builder.Services.AddAuthorization();

// Rate limiting: strict for auth, generous for the rest. Keyed by client IP.
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.AddPolicy("auth", context =>
        RateLimitPartition.GetFixedWindowLimiter(
            context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 10,
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0
            }));
    options.AddPolicy("api", context =>
        RateLimitPartition.GetFixedWindowLimiter(
            context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 120,
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0
            }));
});

var app = builder.Build();

// ---------- Middleware pipeline ----------
// TLS is terminated at the reverse proxy in production; trust forwarded headers.
app.UseForwardedHeaders();
app.UseAuthentication();
app.UseAuthorization();
app.UseRateLimiter();

app.MapControllers();

// ---------- Database: apply migrations, seed admin if configured ----------
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    // SQLite is used only by integration tests; production uses PostgreSQL migrations.
    if (db.Database.ProviderName == "Microsoft.EntityFrameworkCore.Sqlite")
        db.Database.EnsureCreated();
    else
        db.Database.Migrate();

    var seedEmail = builder.Configuration["AdminSeed:Email"];
    var seedPassword = builder.Configuration["AdminSeed:Password"];
    if (!string.IsNullOrWhiteSpace(seedEmail) && !string.IsNullOrWhiteSpace(seedPassword))
    {
        var normalized = seedEmail.Trim().ToLowerInvariant();
        if (!db.Users.Any(u => u.Email == normalized))
        {
            var passwords = scope.ServiceProvider.GetRequiredService<PasswordService>();
            db.Users.Add(new User
            {
                Email = normalized,
                PasswordHash = passwords.Hash(seedPassword),
                IsAdmin = true
            });
            db.SaveChanges();
        }
    }
}

app.Run();

// Exposed for integration tests.
public partial class Program
{
}
