using System;
using Becetti.Security.Api.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

#nullable disable

namespace Becetti.Security.Api.Migrations
{
    [DbContext(typeof(AppDbContext))]
    [Migration("20261120000000_InitialCreate")]
    partial class InitialCreate
    {
        protected override void BuildTargetModel(ModelBuilder modelBuilder)
        {
            modelBuilder
                .HasAnnotation("ProductVersion", "8.0.0")
                .HasAnnotation("Relational:MaxIdentifierLength", 63)
                .UseIdentityByDefaultColumns();

            modelBuilder.Entity("Becetti.Security.Api.Models.AuditLog", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("uuid");

                    b.Property<string>("Action")
                        .IsRequired()
                        .HasColumnType("text");

                    b.Property<string>("Detail")
                        .HasColumnType("text");

                    b.Property<string>("IpAddress")
                        .HasColumnType("text");

                    b.Property<DateTimeOffset>("Timestamp")
                        .HasColumnType("timestamp with time zone");

                    b.Property<Guid?>("UserId")
                        .HasColumnType("uuid");

                    b.HasKey("Id");

                    b.HasIndex("Timestamp");

                    b.ToTable("AuditLogs");
                });

            modelBuilder.Entity("Becetti.Security.Api.Models.RefreshToken", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("uuid");

                    b.Property<DateTimeOffset>("CreatedAt")
                        .HasColumnType("timestamp with time zone");

                    b.Property<DateTimeOffset>("ExpiresAt")
                        .HasColumnType("timestamp with time zone");

                    b.Property<DateTimeOffset?>("RevokedAt")
                        .HasColumnType("timestamp with time zone");

                    b.Property<string>("TokenHash")
                        .IsRequired()
                        .HasColumnType("text");

                    b.Property<Guid>("UserId")
                        .HasColumnType("uuid");

                    b.HasKey("Id");

                    b.HasIndex("TokenHash")
                        .IsUnique();

                    b.HasIndex("UserId");

                    b.ToTable("RefreshTokens");
                });

            modelBuilder.Entity("Becetti.Security.Api.Models.ReleaseVersion", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("uuid");

                    b.Property<string>("Channel")
                        .IsRequired()
                        .HasColumnType("text");

                    b.Property<bool>("IsMandatory")
                        .HasColumnType("boolean");

                    b.Property<DateTimeOffset>("PublishedAt")
                        .HasColumnType("timestamp with time zone");

                    b.Property<string>("ReleaseNotes")
                        .HasColumnType("text");

                    b.Property<string>("StoreUrl")
                        .HasColumnType("text");

                    b.Property<string>("Version")
                        .IsRequired()
                        .HasColumnType("text");

                    b.HasKey("Id");

                    b.HasIndex("Channel", "Version")
                        .IsUnique();

                    b.ToTable("ReleaseVersions");
                });

            modelBuilder.Entity("Becetti.Security.Api.Models.ReputationEntry", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("uuid");

                    b.Property<string>("Detail")
                        .HasColumnType("text");

                    b.Property<DateTimeOffset>("FirstSeenAt")
                        .HasColumnType("timestamp with time zone");

                    b.Property<DateTimeOffset>("LastCheckedAt")
                        .HasColumnType("timestamp with time zone");

                    b.Property<string>("Sha256")
                        .IsRequired()
                        .HasColumnType("text");

                    b.Property<string>("Source")
                        .IsRequired()
                        .HasColumnType("text");

                    b.Property<long>("TimesSeen")
                        .HasColumnType("bigint");

                    b.Property<string>("Verdict")
                        .IsRequired()
                        .HasColumnType("text");

                    b.HasKey("Id");

                    b.HasIndex("Sha256")
                        .IsUnique();

                    b.ToTable("ReputationEntries");
                });

            modelBuilder.Entity("Becetti.Security.Api.Models.User", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("uuid");

                    b.Property<DateTimeOffset>("CreatedAt")
                        .HasColumnType("timestamp with time zone");

                    b.Property<string>("Email")
                        .IsRequired()
                        .HasColumnType("text");

                    b.Property<bool>("IsAdmin")
                        .HasColumnType("boolean");

                    b.Property<string>("PasswordHash")
                        .IsRequired()
                        .HasColumnType("text");

                    b.HasKey("Id");

                    b.HasIndex("Email")
                        .IsUnique();

                    b.ToTable("Users");
                });

            modelBuilder.Entity("Becetti.Security.Api.Models.RefreshToken", b =>
                {
                    b.HasOne("Becetti.Security.Api.Models.User", "User")
                        .WithMany("RefreshTokens")
                        .HasForeignKey("UserId")
                        .OnDelete(DeleteBehavior.Cascade)
                        .IsRequired();

                    b.Navigation("User");
                });

            modelBuilder.Entity("Becetti.Security.Api.Models.User", b =>
                {
                    b.Navigation("RefreshTokens");
                });
        }
    }
}
