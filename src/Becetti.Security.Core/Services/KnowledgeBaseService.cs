using Becetti.Security.Core.Models;

namespace Becetti.Security.Core.Services;

/// <summary>
/// A small, fixed, locally-authored set of security articles. Content is
/// hard-coded in this file (not fetched or AI-generated at runtime) so it
/// works fully offline and its wording can be reviewed like any other code.
/// </summary>
public sealed class KnowledgeBaseService : IKnowledgeBaseService
{
    private static readonly IReadOnlyList<KnowledgeBaseArticle> Articles = new List<KnowledgeBaseArticle>
    {
        new()
        {
            Id = "defender-basics",
            Title = "What Microsoft Defender actually protects you from",
            Category = "Antivirus",
            Body = "Microsoft Defender's real-time protection scans files as they are opened, downloaded " +
                   "or run, and its cloud-delivered protection checks suspicious files against Microsoft's " +
                   "live threat database. BECETTI SECURITY does not replace Defender — it gives you a " +
                   "clearer view of its real status and lets you trigger genuine scans and updates through " +
                   "it. Keep real-time protection and Tamper Protection on at all times."
        },
        new()
        {
            Id = "firewall-basics",
            Title = "Why all three firewall profiles matter",
            Category = "Network",
            Body = "Windows Firewall has separate Domain, Private and Public profiles so it can apply " +
                   "different rules depending on the network you're connected to. If even one profile is " +
                   "off, that type of network is unprotected. The Network Monitor and Vulnerability " +
                   "Advisor pages both show you the real state of each profile."
        },
        new()
        {
            Id = "usb-autorun",
            Title = "The USB autorun risk, and what's already fixed",
            Category = "USB",
            Body = "Older Windows versions would automatically run a program listed in a USB drive's " +
                   "autorun.inf file the moment it was plugged in — a classic malware spreading trick. " +
                   "Windows has disabled this for non-optical removable media by default since a 2011 " +
                   "security update, and the USB Protection page lets you also enforce it explicitly " +
                   "through policy and scan any drive with Defender before opening it."
        },
        new()
        {
            Id = "bitlocker-tpm",
            Title = "TPM, Secure Boot and BitLocker — how they fit together",
            Category = "Platform security",
            Body = "The TPM is a small hardware chip that securely stores encryption keys. Secure Boot " +
                   "stops unsigned/untrusted code from running during startup. BitLocker uses the TPM to " +
                   "encrypt your whole drive so the data is unreadable if the disk is removed and read " +
                   "elsewhere. Identity Protection shows the real, verified state of all three on your PC."
        },
        new()
        {
            Id = "scheduled-scan",
            Title = "Why a scheduled scan should run even when the app is closed",
            Category = "Scanning",
            Body = "Scheduled Scan registers a real Windows Scheduled Task that runs Defender's own " +
                   "MpCmdRun.exe scanner on your chosen daily time — visible and editable in Task " +
                   "Scheduler itself. This means your PC still gets scanned on schedule even if BECETTI " +
                   "SECURITY isn't open at the time."
        },
        new()
        {
            Id = "backups-matter",
            Title = "Antivirus is not a backup",
            Category = "Backup",
            Body = "No antivirus, including Defender, can guarantee recovery from every possible threat " +
                   "(e.g. ransomware that encrypts files before being detected, or hardware failure). File " +
                   "History and System Restore are Windows' own, separate safety nets. Backup Advisor " +
                   "shows whether they are actually configured on this PC — set them up before you need them."
        },
        new()
        {
            Id = "wifi-security",
            Title = "Open Wi-Fi vs. WPA2/WPA3",
            Category = "Network",
            Body = "An 'Open' Wi-Fi network has no encryption at all — anyone nearby can read unencrypted " +
                   "traffic on it. WPA2-Personal and WPA3-Personal encrypt traffic between your device and " +
                   "the router. Wi-Fi Security shows the real authentication type of the network you're " +
                   "currently connected to so you know which kind you're on."
        },
        new()
        {
            Id = "cloud-account",
            Title = "What BECETTI's cloud account is used for",
            Category = "Cloud",
            Body = "Signing in to your BECETTI cloud account lets this app check file reputations and " +
                   "available updates against the BECETTI backend. The Cloud Sync page shows the real, " +
                   "current connectivity and sign-in state of that account — BECETTI SECURITY never " +
                   "invents a 'synced' status it hasn't actually verified."
        }
    };

    public IReadOnlyList<KnowledgeBaseArticle> GetArticles() => Articles;

    public IReadOnlyList<KnowledgeBaseArticle> Search(string query)
    {
        if (string.IsNullOrWhiteSpace(query))
            return Articles;

        return Articles
            .Where(a => a.Title.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                        a.Category.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                        a.Body.Contains(query, StringComparison.OrdinalIgnoreCase))
            .ToList();
    }
}
