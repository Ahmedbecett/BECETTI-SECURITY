using System.Text.RegularExpressions;
using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

/// <summary>
/// Real Clipboard Hijack Guard:
/// Detects clipper malware that silently replaces copied cryptocurrency wallet addresses
/// (BTC, ETH, TRX, LTC, SOL, XMR) or IBANs within a short window after copying.
/// </summary>
public interface IClipboardGuardService
{
    bool IsEnabled { get; set; }
    IReadOnlyList<ClipboardHijackAlert> RecentAlerts { get; }

    event EventHandler<ClipboardHijackAlert>? HijackDetected;

    /// <summary>Evaluates a newly observed clipboard text value and returns an alert if a rapid address swap occurred.</summary>
    ClipboardHijackAlert? ObserveClipboardText(string? text, DateTimeOffset? observedAt = null);

    /// <summary>Classifies whether text is a sensitive financial/wallet address.</summary>
    string? ClassifySensitiveAddress(string? text);
}

public sealed class ClipboardGuardService : IClipboardGuardService
{
    private static readonly TimeSpan HijackWindow = TimeSpan.FromSeconds(5);

    private static readonly (string Name, Regex Pattern)[] AddressPatterns =
    {
        ("Bitcoin (Bech32)", new Regex(@"^bc1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{25,62}$", RegexOptions.Compiled)),
        ("Bitcoin (Legacy/SegWit)", new Regex(@"^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$", RegexOptions.Compiled)),
        ("Ethereum / EVM", new Regex(@"^0x[a-fA-F0-9]{40}$", RegexOptions.Compiled)),
        ("TRON (TRX)", new Regex(@"^T[1-9A-HJ-NP-Za-km-z]{33}$", RegexOptions.Compiled)),
        ("Litecoin (LTC)", new Regex(@"^(?:ltc1[a-z0-9]{39,59}|[LM3][a-km-zA-HJ-NP-Z1-9]{26,33})$", RegexOptions.Compiled)),
        ("Monero (XMR)", new Regex(@"^4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}$", RegexOptions.Compiled)),
        ("IBAN", new Regex(@"^[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}$", RegexOptions.Compiled))
    };

    private readonly List<ClipboardHijackAlert> _alerts = new();
    private readonly object _sync = new();
    private string? _lastAssetType;
    private string? _lastValue;
    private DateTimeOffset _lastObservedAt;

    public bool IsEnabled { get; set; }

    public IReadOnlyList<ClipboardHijackAlert> RecentAlerts
    {
        get
        {
            lock (_sync)
                return _alerts.AsEnumerable().Reverse().ToList();
        }
    }

    public event EventHandler<ClipboardHijackAlert>? HijackDetected;

    public string? ClassifySensitiveAddress(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
            return null;

        var trimmed = text.Trim();
        if (trimmed.Length < 15 || trimmed.Length > 120 || trimmed.Contains(' '))
            return null;

        foreach (var (name, pattern) in AddressPatterns)
        {
            if (pattern.IsMatch(trimmed))
                return name;
        }
        return null;
    }

    public ClipboardHijackAlert? ObserveClipboardText(string? text, DateTimeOffset? observedAt = null)
    {
        if (!IsEnabled)
            return null;

        var now = observedAt ?? DateTimeOffset.UtcNow;
        var assetType = ClassifySensitiveAddress(text);
        if (assetType is null)
            return null;

        var trimmed = text!.Trim();
        ClipboardHijackAlert? alert = null;

        lock (_sync)
        {
            if (_lastValue is not null &&
                !string.Equals(_lastValue, trimmed, StringComparison.Ordinal) &&
                string.Equals(_lastAssetType, assetType, StringComparison.Ordinal) &&
                (now - _lastObservedAt) <= HijackWindow)
            {
                alert = new ClipboardHijackAlert
                {
                    DetectedAt = now,
                    AssetType = assetType,
                    OriginalValue = _lastValue,
                    ReplacedValue = trimmed,
                    Message = $"Possible clipboard hijacker! {assetType} address changed within {(now - _lastObservedAt).TotalSeconds:F1}s from '{Mask(_lastValue)}' to '{Mask(trimmed)}'."
                };
                _alerts.Add(alert);
                if (_alerts.Count > 50)
                    _alerts.RemoveAt(0);
            }

            _lastAssetType = assetType;
            _lastValue = trimmed;
            _lastObservedAt = now;
        }

        if (alert is not null)
            HijackDetected?.Invoke(this, alert);

        return alert;
    }

    private static string Mask(string value) =>
        value.Length <= 12 ? value : $"{value[..6]}...{value[^4..]}";
}
