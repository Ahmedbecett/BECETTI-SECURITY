using Becetti.Security.Api.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

namespace Becetti.Security.Api.Data;

/// <summary>PostgreSQL database context. Schema is managed by EF Core migrations.</summary>
public sealed class AppDbContext : DbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
    {
    }

    public DbSet<User> Users => Set<User>();
    public DbSet<RefreshToken> RefreshTokens => Set<RefreshToken>();
    public DbSet<ReputationEntry> ReputationEntries => Set<ReputationEntry>();
    public DbSet<ReleaseVersion> ReleaseVersions => Set<ReleaseVersion>();
    public DbSet<AuditLog> AuditLogs => Set<AuditLog>();
    public DbSet<Device> Devices => Set<Device>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<User>(entity =>
        {
            entity.HasIndex(e => e.Email).IsUnique();
        });

        modelBuilder.Entity<RefreshToken>(entity =>
        {
            entity.HasIndex(e => e.TokenHash).IsUnique();
            entity.HasOne(e => e.User)
                .WithMany(u => u.RefreshTokens)
                .HasForeignKey(e => e.UserId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<ReputationEntry>(entity =>
        {
            entity.HasIndex(e => e.Sha256).IsUnique();
        });

        modelBuilder.Entity<ReleaseVersion>(entity =>
        {
            entity.HasIndex(e => new { e.Channel, e.Version }).IsUnique();
        });

        modelBuilder.Entity<AuditLog>(entity =>
        {
            entity.HasIndex(e => e.Timestamp);
        });

        modelBuilder.Entity<Device>(entity =>
        {
            entity.HasIndex(e => new { e.UserId, e.DeviceId }).IsUnique();
            entity.HasOne(e => e.User)
                .WithMany(u => u.Devices)
                .HasForeignKey(e => e.UserId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        // SQLite (used only by the integration test host, never in production) has no
        // native DateTimeOffset comparison/ordering support: "SQLite cannot order by
        // expressions of type 'DateTimeOffset'" (NotSupportedException) hits every
        // OrderBy(... .PublishedAt/Timestamp/etc.) query at runtime even though the model
        // and migrations are correct. PostgreSQL has no such limitation, so this conversion
        // is applied only when the active provider actually is Sqlite.
        if (Database.ProviderName == "Microsoft.EntityFrameworkCore.Sqlite")
        {
            var converter = new DateTimeOffsetToBinaryConverter();
            foreach (var entityType in modelBuilder.Model.GetEntityTypes())
            {
                foreach (var property in entityType.ClrType.GetProperties())
                {
                    if (property.PropertyType == typeof(DateTimeOffset) || property.PropertyType == typeof(DateTimeOffset?))
                    {
                        modelBuilder.Entity(entityType.Name).Property(property.Name).HasConversion(converter);
                    }
                }
            }
        }
    }
}
