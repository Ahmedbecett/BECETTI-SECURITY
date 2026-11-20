namespace Becetti.Security.Api.Services;

/// <summary>BCrypt password hashing. Plaintext passwords are never stored or logged.</summary>
public sealed class PasswordService
{
    public string Hash(string password) => BCrypt.Net.BCrypt.HashPassword(password, workFactor: 12);

    public bool Verify(string password, string hash)
    {
        try
        {
            return BCrypt.Net.BCrypt.Verify(password, hash);
        }
        catch
        {
            return false;
        }
    }
}
