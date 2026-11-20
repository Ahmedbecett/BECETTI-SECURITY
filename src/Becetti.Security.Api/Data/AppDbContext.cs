using Becetti.Security.Api.Models;
using Microsoft.EntityFrameworkCore;

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
    }
}
