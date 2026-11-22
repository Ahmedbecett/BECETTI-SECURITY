using System.Security.Cryptography;
using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

public interface IAppLockService
{
    bool IsEnabled { get; }
    bool HasPinConfigured { get; }
    bool IsSessionUnlocked { get; }
    void LockSession();
    void MarkSessionUnlocked();
    Task<OperationResult> SetPinAsync(string pin, CancellationToken ct = default);
    Task<OperationResult> ClearPinAsync(CancellationToken ct = default);
    bool VerifyPin(string pin);
}

/// <summary>
/// Real Anti-Tamper App Lock credential manager:
/// secures an optional fallback PIN using 100,000-iteration PBKDF2-SHA256 + 16-byte CSPRNG salt
/// (paired with Windows Hello UserConsentVerifier in the WinUI App layer) and tracks session unlock state.
/// </summary>
public sealed class AppLockService : IAppLockService
{
    private const int Pbkdf2Iterations = 100_000;
    private readonly ISettingsService _settings;

    public bool IsEnabled => _settings.Current.AppLockEnabled;
    public bool HasPinConfigured => !string.IsNullOrWhiteSpace(_settings.Current.AppLockPinHash) &&
                                    !string.IsNullOrWhiteSpace(_settings.Current.AppLockPinSalt);
    public bool IsSessionUnlocked { get; private set; }

    public AppLockService(ISettingsService settings)
    {
        _settings = settings;
    }

    public void LockSession() => IsSessionUnlocked = false;
    public void MarkSessionUnlocked() => IsSessionUnlocked = true;

    public async Task<OperationResult> SetPinAsync(string pin, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(pin) || pin.Trim().Length < 4 || pin.Trim().Length > 32)
            return OperationResult.Fail("Security PIN must be between 4 and 32 characters.", "INVALID_PIN");

        var salt = RandomNumberGenerator.GetBytes(16);
        var hash = DeriveHash(pin.Trim(), salt);

        _settings.Current.AppLockPinSalt = Convert.ToBase64String(salt);
        _settings.Current.AppLockPinHash = Convert.ToBase64String(hash);
        _settings.Current.AppLockEnabled = true;
        IsSessionUnlocked = true;
        await _settings.SaveAsync(ct).ConfigureAwait(false);
        return OperationResult.Ok("Anti-Tamper App Lock PIN saved (PBKDF2-SHA256).");
    }

    public async Task<OperationResult> ClearPinAsync(CancellationToken ct = default)
    {
        _settings.Current.AppLockPinSalt = string.Empty;
        _settings.Current.AppLockPinHash = string.Empty;
        _settings.Current.AppLockEnabled = false;
        IsSessionUnlocked = true;
        await _settings.SaveAsync(ct).ConfigureAwait(false);
        return OperationResult.Ok("Anti-Tamper App Lock disabled.");
    }

    public bool VerifyPin(string pin)
    {
        if (string.IsNullOrWhiteSpace(pin) || !HasPinConfigured)
            return false;

        try
        {
            var salt = Convert.FromBase64String(_settings.Current.AppLockPinSalt);
            var expected = Convert.FromBase64String(_settings.Current.AppLockPinHash);
            var actual = DeriveHash(pin.Trim(), salt);
            bool match = CryptographicOperations.FixedTimeEquals(expected, actual);
            if (match)
                IsSessionUnlocked = true;
            return match;
        }
        catch
        {
            return false;
        }
    }

    private static byte[] DeriveHash(string pin, byte[] salt) =>
        Rfc2898DeriveBytes.Pbkdf2(pin, salt, Pbkdf2Iterations, HashAlgorithmName.SHA256, 32);
}
