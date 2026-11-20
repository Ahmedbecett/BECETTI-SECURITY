using System.Security.Cryptography;

namespace Becetti.Security.Core.Services;

/// <summary>Local SHA-256 hashing used for cloud reputation lookups. The file itself is never uploaded.</summary>
public static class FileHashService
{
    public static async Task<string> ComputeSha256Async(string path, CancellationToken ct = default)
    {
        if (!File.Exists(path))
            throw new FileNotFoundException("File not found.", path);

        using var stream = File.OpenRead(path);
        using var sha256 = SHA256.Create();
        var hash = await sha256.ComputeHashAsync(stream, ct).ConfigureAwait(false);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    public static bool IsValidSha256(string? value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length != 64)
            return false;

        return value.All(c => (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'));
    }
}
