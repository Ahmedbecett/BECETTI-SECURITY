using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

/// <summary>
/// Settings stored as JSON under %LocalAppData%\BecettiSecurity.
/// Tokens are stored separately and protected with DPAPI (CurrentUser scope)
/// on Windows. On non-Windows hosts protection is unavailable and the store
/// reports ProtectionActive = false instead of pretending otherwise.
/// </summary>
public sealed class SettingsService : ISettingsService
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    public SettingsService(string? dataDirectory = null)
    {
        DataDirectory = dataDirectory ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "BecettiSecurity");
    }

    public AppSettings Current { get; private set; } = new();
    public string DataDirectory { get; }

    private string SettingsPath => Path.Combine(DataDirectory, "settings.json");

    public async Task LoadAsync(CancellationToken ct = default)
    {
        try
        {
            if (!File.Exists(SettingsPath))
            {
                Current = new AppSettings();
                return;
            }

            var json = await File.ReadAllTextAsync(SettingsPath, ct).ConfigureAwait(false);
            Current = JsonSerializer.Deserialize<AppSettings>(json, JsonOptions) ?? new AppSettings();
        }
        catch
        {
            // Corrupt settings must never crash the app; fall back to defaults.
            Current = new AppSettings();
        }
    }

    public async Task SaveAsync(CancellationToken ct = default)
    {
        Directory.CreateDirectory(DataDirectory);
        var json = JsonSerializer.Serialize(Current, JsonOptions);
        await File.WriteAllTextAsync(SettingsPath, json, ct).ConfigureAwait(false);
    }
}

/// <summary>DPAPI-protected token storage.</summary>
public sealed class TokenStore : ITokenStore
{
    private readonly string _filePath;
    private readonly string _entropy = "BECETTI-SECURITY-v1";

    public TokenStore(string? dataDirectory = null)
    {
        var dir = dataDirectory ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "BecettiSecurity");
        _filePath = Path.Combine(dir, "tokens.dat");
    }

    public bool ProtectionActive => OperatingSystem.IsWindows();

    public async Task SaveAsync(AuthTokens tokens, CancellationToken ct = default)
    {
        var json = JsonSerializer.Serialize(tokens);
        var bytes = Encoding.UTF8.GetBytes(json);

        if (ProtectionActive)
        {
            var entropy = Encoding.UTF8.GetBytes(_entropy);
            bytes = ProtectedData.Protect(bytes, entropy, DataProtectionScope.CurrentUser);
        }

        Directory.CreateDirectory(Path.GetDirectoryName(_filePath)!);
        await File.WriteAllBytesAsync(_filePath, bytes, ct).ConfigureAwait(false);
    }

    public async Task<AuthTokens?> LoadAsync(CancellationToken ct = default)
    {
        if (!File.Exists(_filePath))
            return null;

        var bytes = await File.ReadAllBytesAsync(_filePath, ct).ConfigureAwait(false);

        if (ProtectionActive)
        {
            var entropy = Encoding.UTF8.GetBytes(_entropy);
            bytes = ProtectedData.Unprotect(bytes, entropy, DataProtectionScope.CurrentUser);
        }

        var json = Encoding.UTF8.GetString(bytes);
        return JsonSerializer.Deserialize<AuthTokens>(json);
    }

    public Task ClearAsync(CancellationToken ct = default)
    {
        if (File.Exists(_filePath))
            File.Delete(_filePath);
        return Task.CompletedTask;
    }
}
