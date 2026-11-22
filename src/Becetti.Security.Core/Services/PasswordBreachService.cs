using System.Security.Cryptography;
using System.Text;
using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

public interface IPasswordBreachService
{
    Task<OperationResult<PasswordStrengthBreachResult>> CheckPasswordAsync(string password, bool queryHibp = true, CancellationToken ct = default);
}

/// <summary>
/// Real k-Anonymity Password Breach &amp; Entropy Auditor:
/// computes local password strength/entropy and checks HaveIBeenPwned's official
/// Pwned Passwords Range API (https://api.pwnedpasswords.com/range/{first5Sha1}).
/// The plaintext password NEVER leaves the device — only the first 5 SHA-1 hex characters are sent.
/// </summary>
public sealed class PasswordBreachService : IPasswordBreachService
{
    private readonly HttpClient _http;

    public PasswordBreachService(HttpClient http)
    {
        _http = http;
    }

    public async Task<OperationResult<PasswordStrengthBreachResult>> CheckPasswordAsync(string password, bool queryHibp = true, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(password))
            return OperationResult<PasswordStrengthBreachResult>.Fail("Enter a password to evaluate.", "EMPTY_PASSWORD");

        double entropy = ComputeEntropyBits(password);
        string rating = entropy switch
        {
            >= 80 => "Very Strong",
            >= 60 => "Strong",
            >= 40 => "Fair",
            _ => "Weak"
        };

        var sha1Hex = Convert.ToHexString(SHA1.HashData(Encoding.UTF8.GetBytes(password)));
        var prefix = sha1Hex[..5];
        var suffix = sha1Hex[5..];

        bool checkSucceeded = false;
        bool isCompromised = false;
        long breachCount = 0;

        if (queryHibp)
        {
            try
            {
                using var req = new HttpRequestMessage(HttpMethod.Get, $"https://api.pwnedpasswords.com/range/{prefix}");
                req.Headers.TryAddWithoutValidation("User-Agent", "BECETTI-SECURITY/1.0");
                req.Headers.TryAddWithoutValidation("Add-Padding", "true");

                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(TimeSpan.FromSeconds(10));

                using var resp = await _http.SendAsync(req, cts.Token).ConfigureAwait(false);
                if (resp.IsSuccessStatusCode)
                {
                    var body = await resp.Content.ReadAsStringAsync(cts.Token).ConfigureAwait(false);
                    checkSucceeded = true;
                    breachCount = ParseHibpRangeResponse(body, suffix);
                    isCompromised = breachCount > 0;
                }
            }
            catch
            {
                checkSucceeded = false;
            }
        }

        string advice;
        if (isCompromised)
        {
            rating = "Compromised";
            advice = $"CRITICAL: This password appeared in {breachCount:N0} known data breaches! Change it immediately everywhere it is used.";
        }
        else if (entropy < 45)
        {
            advice = "Password is too predictable. Use at least 14+ characters mixing uppercase, lowercase, digits, and symbols (or a 4-word passphrase).";
        }
        else if (checkSucceeded)
        {
            advice = $"Not found in known data breaches (k-Anonymity prefix {prefix}). Strength: {rating} ({entropy:F1} bits).";
        }
        else
        {
            advice = $"Local strength: {rating} ({entropy:F1} bits). Online breach lookup was offline/unavailable.";
        }

        var report = new PasswordStrengthBreachResult
        {
            Length = password.Length,
            EntropyBits = Math.Round(entropy, 1),
            StrengthRating = rating,
            BreachCheckSucceeded = checkSucceeded,
            IsCompromised = isCompromised,
            BreachCount = breachCount,
            Sha1PrefixSent = prefix,
            Advice = advice
        };

        return OperationResult<PasswordStrengthBreachResult>.Ok(report, advice);
    }

    internal static double ComputeEntropyBits(string password)
    {
        if (string.IsNullOrEmpty(password))
            return 0;

        bool hasLower = password.Any(char.IsLower);
        bool hasUpper = password.Any(char.IsUpper);
        bool hasDigit = password.Any(char.IsDigit);
        bool hasSymbol = password.Any(c => !char.IsLetterOrDigit(c));

        int pool = (hasLower ? 26 : 0) + (hasUpper ? 26 : 0) + (hasDigit ? 10 : 0) + (hasSymbol ? 33 : 0);
        if (pool == 0) pool = 10;

        // Discount entropy slightly for repeated characters
        double uniqueRatio = (double)password.Distinct().Count() / password.Length;
        double effectiveLength = password.Length * (0.6 + 0.4 * uniqueRatio);
        return effectiveLength * Math.Log2(pool);
    }

    internal static long ParseHibpRangeResponse(string responseBody, string expectedSuffix)
    {
        if (string.IsNullOrWhiteSpace(responseBody) || string.IsNullOrWhiteSpace(expectedSuffix))
            return 0;

        foreach (var rawLine in responseBody.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
        {
            var sep = rawLine.IndexOf(':');
            if (sep <= 0 || sep + 1 >= rawLine.Length)
                continue;

            var lineSuffix = rawLine[..sep].Trim();
            if (lineSuffix.Equals(expectedSuffix, StringComparison.OrdinalIgnoreCase))
            {
                if (long.TryParse(rawLine[(sep + 1)..].Trim(), out var count))
                    return count;
            }
        }
        return 0;
    }
}
