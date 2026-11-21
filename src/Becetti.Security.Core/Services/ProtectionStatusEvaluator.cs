using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

/// <summary>Aggregate, at-a-glance protection level derived only from real, verified Defender state.</summary>
public enum ProtectionLevel
{
    /// <summary>Status could not be read at all (Defender unreachable). Never shown as "safe".</summary>
    Unknown,
    /// <summary>Antivirus is enabled and real-time protection is active (or genuinely handled by another AV).</summary>
    Protected,
    /// <summary>Something needs attention: real-time protection is off, or another product manages protection.</summary>
    Warning,
    /// <summary>Antivirus itself is disabled with nothing else managing protection.</summary>
    Danger
}

/// <summary>
/// Pure function over a verified DefenderStatus. Contains no Windows calls of its own —
/// it only classifies data that GetStatusAsync already read from Get-MpComputerStatus /
/// Get-MpPreference, so it is fully unit-testable without a live Defender instance.
/// </summary>
public static class ProtectionStatusEvaluator
{
    public static ProtectionLevel Evaluate(DefenderStatus? status)
    {
        if (status is null || !status.Available)
            return ProtectionLevel.Unknown;

        if (!status.AntivirusEnabled)
            return ProtectionLevel.Danger;

        if (status.ManagedByAnotherAntivirus)
            return ProtectionLevel.Warning;

        if (!status.RealTimeProtectionEnabled)
            return ProtectionLevel.Warning;

        return ProtectionLevel.Protected;
    }
}
