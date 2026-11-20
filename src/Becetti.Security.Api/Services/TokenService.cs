using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Becetti.Security.Api.Models;
using Microsoft.IdentityModel.Tokens;

namespace Becetti.Security.Api.Services;

/// <summary>JWT access-token issuance and refresh-token hashing.</summary>
public sealed class TokenService
{
    private readonly IConfiguration _configuration;

    public TokenService(IConfiguration configuration)
    {
        _configuration = configuration;
    }

    public (string AccessToken, DateTimeOffset ExpiresAt) CreateAccessToken(User user)
    {
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(GetSigningKey()));
        var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var expiresAt = DateTimeOffset.UtcNow.AddMinutes(GetAccessTokenMinutes());
        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
            new Claim(JwtRegisteredClaimNames.Email, user.Email),
            new Claim(ClaimTypes.Role, user.IsAdmin ? "Admin" : "User"),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };

        var token = new JwtSecurityToken(
            issuer: GetIssuer(),
            audience: GetAudience(),
            claims: claims,
            notBefore: DateTime.UtcNow,
            expires: expiresAt.UtcDateTime,
            signingCredentials: credentials);

        return (new JwtSecurityTokenHandler().WriteToken(token), expiresAt);
    }

    public string CreateRefreshToken()
    {
        var bytes = RandomNumberGenerator.GetBytes(64);
        return Convert.ToBase64String(bytes);
    }

    public static string HashToken(string token)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(token));
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private string GetSigningKey()
    {
        var key = _configuration["Jwt:SigningKey"];
        if (string.IsNullOrWhiteSpace(key) || key.Length < 32)
            throw new InvalidOperationException("Jwt:SigningKey must be set via environment variable and be at least 32 characters long.");
        return key;
    }

    private string GetIssuer() => _configuration["Jwt:Issuer"] ?? "becetti-security-api";
    private string GetAudience() => _configuration["Jwt:Audience"] ?? "becetti-security-app";

    private int GetAccessTokenMinutes()
    {
        var raw = _configuration["Jwt:AccessTokenMinutes"];
        return int.TryParse(raw, out var minutes) && minutes > 0 ? minutes : 60;
    }
}
