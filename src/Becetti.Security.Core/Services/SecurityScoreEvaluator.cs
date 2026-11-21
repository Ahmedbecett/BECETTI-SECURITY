using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

/// <summary>
/// Pure function that turns already-verified Defender/firewall/Controlled
/// Folder Access state into a 0-100 security score with a named factor list.
/// No Windows calls of its own and no randomness: the same inputs always
/// produce the same score, and every point gained or lost is tied to a real,
/// named signal the caller already read from a real Windows interface.
/// </summary>
public static class SecurityScoreEvaluator
{
    public static SecurityScoreResult Evaluate(
        DefenderStatus? defender,
        IReadOnlyList<FirewallProfileStatus>? firewall,
        RansomwareProtectionStatus? ransomware)
    {
        if (defender is null || !defender.Available)
        {
            return new SecurityScoreResult
            {
                Score = null,
                Factors = new[]
                {
                    new SecurityScoreFactor
                    {
                        Title = "Microsoft Defender status unknown",
                        Detail = "BECETTI SECURITY could not read Microsoft Defender's status, so no score can be calculated yet.",
                        PointsDelta = 0
                    }
                }
            };
        }

        var score = 0;
        var factors = new List<SecurityScoreFactor>();

        void Add(int delta, string title, string detail)
        {
            score += delta;
            factors.Add(new SecurityScoreFactor { Title = title, Detail = detail, PointsDelta = delta });
        }

        // Antivirus (30 pts)
        if (defender.AntivirusEnabled)
            Add(30, "Antivirus is enabled", "Microsoft Defender's antivirus engine is active.");
        else
            Add(-30, "Antivirus is disabled", "Microsoft Defender's antivirus engine is off. Your device has no active malware protection.");

        // Real-time protection (25 pts)
        if (defender.ManagedByAnotherAntivirus)
            Add(15, "Protection managed by another antivirus", $"Defender reports running mode '{defender.RunningMode}', meaning a different antivirus product is the active real-time engine.");
        else if (defender.RealTimeProtectionEnabled)
            Add(25, "Real-time protection is on", "Microsoft Defender is actively monitoring for threats as they appear.");
        else
            Add(-25, "Real-time protection is off", "Files and downloads are not being scanned automatically.");

        // Tamper protection (10 pts)
        if (defender.TamperProtectionEnabled)
            Add(10, "Tamper protection is on", "Security settings are protected from unauthorized changes, including by malware.");
        else
            Add(-10, "Tamper protection is off", "Malicious software or other users could change your security settings.");

        // Cloud-delivered protection (10 pts)
        if (string.Equals(defender.CloudProtectionLevel, "Advanced", StringComparison.OrdinalIgnoreCase))
            Add(10, "Cloud-delivered protection: Advanced", "Defender shares more data with Microsoft's cloud for faster detection of new threats.");
        else if (string.Equals(defender.CloudProtectionLevel, "Basic", StringComparison.OrdinalIgnoreCase))
            Add(6, "Cloud-delivered protection: Basic", "Basic cloud protection is on; Advanced gives faster detection of brand-new threats.");
        else if (string.Equals(defender.CloudProtectionLevel, "Disabled", StringComparison.OrdinalIgnoreCase))
            Add(-10, "Cloud-delivered protection is off", "Defender cannot check suspicious files against Microsoft's real-time cloud intelligence.");

        // Signature freshness (10 pts)
        if (defender.AntivirusSignatureLastUpdated is { } updated)
        {
            var age = DateTimeOffset.Now - updated;
            if (age <= TimeSpan.FromDays(3))
                Add(10, "Security intelligence is current", $"Virus definitions were last updated {FormatAge(age)}.");
            else if (age <= TimeSpan.FromDays(10))
                Add(2, "Security intelligence is aging", $"Virus definitions were last updated {FormatAge(age)}. Run an update soon.");
            else
                Add(-10, "Security intelligence is out of date", $"Virus definitions were last updated {FormatAge(age)}. New threats may not be recognized.");
        }

        // Firewall (10 pts total across profiles actually read)
        if (firewall is { Count: > 0 })
        {
            var enabledCount = firewall.Count(p => p.Enabled);
            if (enabledCount == firewall.Count)
                Add(10, "Firewall is on for all profiles", $"All {firewall.Count} Windows Firewall profile(s) are enabled.");
            else if (enabledCount > 0)
                Add(3, "Firewall is only partially on", $"{enabledCount} of {firewall.Count} Windows Firewall profile(s) are enabled.");
            else
                Add(-10, "Firewall is off", "No Windows Firewall profile is currently enabled.");
        }

        // Ransomware protection / Controlled Folder Access (5 pts)
        if (ransomware is { Available: true })
        {
            if (ransomware.ControlledFolderAccessEnabled)
                Add(5, "Ransomware protection is on", "Controlled Folder Access is blocking unauthorized changes to your protected folders.");
            else
                Add(0, "Ransomware protection is off", "Controlled Folder Access is disabled. Turning it on adds another layer of defense against ransomware.");
        }

        var clamped = Math.Clamp(score, 0, 100);
        return new SecurityScoreResult { Score = clamped, Factors = factors };
    }

    private static string FormatAge(TimeSpan age)
    {
        if (age.TotalDays >= 1)
            return $"{(int)age.TotalDays} day(s) ago";
        if (age.TotalHours >= 1)
            return $"{(int)age.TotalHours} hour(s) ago";
        return "less than an hour ago";
    }
}
