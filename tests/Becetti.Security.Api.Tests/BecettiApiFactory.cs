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

    public BecettiApiFactory()
    {
        _connection.Open();
    }

    protected override void ConfigureWebHost(Microsoft.AspNetCore.Hosting.IWebHostBuilder builder)
    {
        builder.ConfigureAppConfiguration((context, config) =>
        {
            config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:Postgres"] = "Host=localhost;Database=unused-in-tests",
                ["Jwt:SigningKey"] = "test-signing-key-that-is-long-enough-1234567890",
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
