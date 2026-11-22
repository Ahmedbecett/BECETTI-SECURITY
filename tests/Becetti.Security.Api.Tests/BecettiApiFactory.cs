using Becetti.Security.Api.Data;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Becetti.Security.Api.Tests;

/// <summary>
/// Integration-test host: swaps PostgreSQL for a shared in-memory SQLite
/// database and supplies test configuration (no real secrets).
/// </summary>
public sealed class BecettiApiFactory : WebApplicationFactory<Program>, IDisposable
{
    private readonly SqliteConnection _connection = new("DataSource=:memory:");

    // Test signing key, shared by every reader of Jwt:SigningKey below (env var,
    // ConfigureAppConfiguration and the assertion that both ended up in sync).
    private const string TestSigningKey = "test-signing-key-that-is-long-enough-1234567890";

    public BecettiApiFactory()
    {
        _connection.Open();

        // Program.cs reads Jwt:SigningKey and ConnectionStrings:Postgres into plain local
        // variables at the very top of its top-level statements - BEFORE WebApplicationBuilder.Build()
        // runs. WebApplicationFactory's ConfigureWebHost/ConfigureAppConfiguration callbacks below are
        // only merged into the configuration pipeline when Build() itself executes, so they are
        // invisible to those early reads. The result: TokenService (resolved from DI at request time,
        // after Build() has finished) signs JWTs with the test key from ConfigureAppConfiguration, but
        // AddJwtBearer's TokenValidationParameters.IssuerSigningKey - captured from that early read -
        // still holds appsettings.json's placeholder key. Every signature check then fails and every
        // authenticated endpoint returns 401, regardless of how valid the token looks.
        //
        // Environment variables are read synchronously by WebApplication.CreateBuilder(args) itself,
        // before any of Program.cs's own code runs, so setting them here (using the app's documented
        // double-underscore convention, e.g. Jwt__SigningKey) is visible to those early reads too.
        Environment.SetEnvironmentVariable("ConnectionStrings__Postgres", "Host=localhost;Database=unused-in-tests");
        Environment.SetEnvironmentVariable("Jwt__SigningKey", TestSigningKey);
        Environment.SetEnvironmentVariable("Jwt__Issuer", "becetti-security-api");
        Environment.SetEnvironmentVariable("Jwt__Audience", "becetti-security-app");
        Environment.SetEnvironmentVariable("VirusTotal__ApiKey", string.Empty);
    }

    protected override void ConfigureWebHost(Microsoft.AspNetCore.Hosting.IWebHostBuilder builder)
    {
        // Kept in addition to the environment variables above for anything that reads
        // configuration lazily through IConfiguration/IOptions after the host is built.
        builder.ConfigureAppConfiguration((context, config) =>
        {
            config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:Postgres"] = "Host=localhost;Database=unused-in-tests",
                ["Jwt:SigningKey"] = TestSigningKey,
                ["Jwt:Issuer"] = "becetti-security-api",
                ["Jwt:Audience"] = "becetti-security-app",
                ["VirusTotal:ApiKey"] = string.Empty
            });
        });

        builder.ConfigureServices(services =>
        {
            // Removing only AppDbContext leaves Program.cs's UseNpgsql(...) options/provider
            // configuration registered, so EF Core would see two providers (Npgsql + Sqlite)
            // for the same context and throw at startup. Remove every registration AddDbContext
            // created (the context itself and its options) first.
            //
            // Note: EF Core 9+ also registers IDbContextOptionsConfiguration<TContext>, which
            // would need removing too on that version. This project pins EF Core 8.0.*, where
            // that interface does not exist yet, so it is intentionally not referenced here.
            services.RemoveAll<AppDbContext>();
            services.RemoveAll<DbContextOptions<AppDbContext>>();
            services.RemoveAll<DbContextOptions>();

            services.AddDbContext<AppDbContext>(options =>
            {
                options.UseSqlite(_connection);
            });
        });
    }

    public new void Dispose()
    {
        _connection.Dispose();
        base.Dispose();
    }
}
