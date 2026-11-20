using Becetti.Security.Api.Data;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
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
            services.RemoveAll<AppDbContext>();
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
