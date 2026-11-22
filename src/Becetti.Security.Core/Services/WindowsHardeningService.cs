using System.Diagnostics;
using System.Runtime.Versioning;
using Becetti.Security.Core.Models;
using Microsoft.Win32;

namespace Becetti.Security.Core.Services;

public interface IWindowsHardeningService
{
    Task<OperationResult<WindowsHardeningReport>> AuditAsync(CancellationToken ct = default);
}

/// <summary>
/// Real Windows Hardening & Attack Surface Auditor:
/// verifies live OS & hardware security posture from Windows Registry and system tools:
/// UAC, UEFI Secure Boot, Core Isolation (HVCI Memory Integrity), SMBv1 disabled,
/// RDP exposure & NLA, TPM 2.0 readiness, BitLocker drive encryption,
/// Controlled Folder Access, and Windows Firewall profiles. Zero simulation.
/// </summary>
public sealed class WindowsHardeningService : IWindowsHardeningService
{
    public async Task<OperationResult<WindowsHardeningReport>> AuditAsync(CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
            return OperationResult<WindowsHardeningReport>.Fail("Windows Hardening Audit requires Windows.", "UNSUPPORTED_OS");

        var checks = new List<HardeningCheckItem>();

        await Task.Run(() =>
        {
            checks.Add(CheckUac());
            checks.Add(CheckSecureBoot());
            checks.Add(CheckCoreIsolationHvci());
            checks.Add(CheckSmbV1());
            checks.Add(CheckRdpExposure());
            checks.Add(CheckControlledFolderAccess());
            checks.Add(CheckWindowsFirewallProfiles());
            checks.Add(CheckTpmService());
        }, ct).ConfigureAwait(false);

        checks.Add(await CheckBitLockerAsync(ct).ConfigureAwait(false));

        var evaluable = checks.Where(c => c.Status != "Unavailable").ToList();
        int passed = evaluable.Count(c => c.Status == "Passed");
        int warning = evaluable.Count(c => c.Status == "Warning");
        int failed = evaluable.Count(c => c.Status == "Failed");

        int score = evaluable.Count == 0
            ? 0
            : (int)Math.Round(((passed * 1.0) + (warning * 0.5)) / evaluable.Count * 100.0);

        var report = new WindowsHardeningReport
        {
            AuditedAt = DateTimeOffset.UtcNow,
            ScorePercent = Math.Clamp(score, 0, 100),
            PassedCount = passed,
            WarningCount = warning,
            FailedCount = failed,
            TotalEvaluated = evaluable.Count,
            Checks = checks
        };

        return OperationResult<WindowsHardeningReport>.Ok(
            report,
            $"Windows Hardening Score: {report.ScorePercent}% ({passed} passed, {warning} warnings, {failed} failed).");
    }

    [SupportedOSPlatform("windows")]
    private static HardeningCheckItem CheckUac()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System");
            int lua = Convert.ToInt32(key?.GetValue("EnableLUA") ?? 0);
            int prompt = Convert.ToInt32(key?.GetValue("ConsentPromptBehaviorAdmin") ?? 0);
            if (lua == 1 && prompt > 0)
                return Item("uac", "Privilege", "User Account Control (UAC)", "Passed", "Enabled with admin consent prompt", "Keep UAC enabled.");
            if (lua == 1)
                return Item("uac", "Privilege", "User Account Control (UAC)", "Warning", "Enabled but set to auto-elevate silently", "Set UAC to 'Notify me when apps try to make changes'.");
            return Item("uac", "Privilege", "User Account Control (UAC)", "Failed", "Disabled (EnableLUA=0)", "Enable UAC immediately to block silent privilege escalation.");
        }
        catch (Exception ex) { return Unavailable("uac", "Privilege", "User Account Control (UAC)", ex.Message); }
    }

    [SupportedOSPlatform("windows")]
    private static HardeningCheckItem CheckSecureBoot()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\SecureBoot\State");
            var val = key?.GetValue("UEFISecureBootEnabled");
            if (val is null)
                return Item("secureboot", "Firmware", "UEFI Secure Boot", "Warning", "Not reported (Legacy BIOS or VM firmware)", "Enable UEFI Secure Boot in BIOS/UEFI firmware if supported.");
            int enabled = Convert.ToInt32(val);
            return enabled == 1
                ? Item("secureboot", "Firmware", "UEFI Secure Boot", "Passed", "Enabled", "Verified firmware boot integrity active.")
                : Item("secureboot", "Firmware", "UEFI Secure Boot", "Failed", "Disabled", "Enable Secure Boot in UEFI settings to block bootkits.");
        }
        catch (Exception ex) { return Unavailable("secureboot", "Firmware", "UEFI Secure Boot", ex.Message); }
    }

    [SupportedOSPlatform("windows")]
    private static HardeningCheckItem CheckCoreIsolationHvci()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity");
            int enabled = Convert.ToInt32(key?.GetValue("Enabled") ?? 0);
            return enabled == 1
                ? Item("hvci", "Kernel", "Core Isolation (Memory Integrity / HVCI)", "Passed", "Enabled", "Kernel code integrity is hardware-protected.")
                : Item("hvci", "Kernel", "Core Isolation (Memory Integrity / HVCI)", "Warning", "Disabled", "Enable Memory Integrity in Windows Security -> Device Security -> Core Isolation.");
        }
        catch (Exception ex) { return Unavailable("hvci", "Kernel", "Core Isolation (Memory Integrity / HVCI)", ex.Message); }
    }

    [SupportedOSPlatform("windows")]
    private static HardeningCheckItem CheckSmbV1()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters");
            var val = key?.GetValue("SMB1");
            // On modern Windows 10/11, absent or 0 means disabled
            int smb1 = val is null ? 0 : Convert.ToInt32(val);
            return smb1 == 0
                ? Item("smbv1", "Network", "SMBv1 Legacy Protocol Disabled", "Passed", "Disabled", "Protected against WannaCry / EternalBlue SMBv1 exploits.")
                : Item("smbv1", "Network", "SMBv1 Legacy Protocol Disabled", "Failed", "Enabled (SMB1=1)", "Disable SMBv1 immediately via Turn Windows Features On or Off.");
        }
        catch (Exception ex) { return Unavailable("smbv1", "Network", "SMBv1 Legacy Protocol Disabled", ex.Message); }
    }

    [SupportedOSPlatform("windows")]
    private static HardeningCheckItem CheckRdpExposure()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Terminal Server");
            int deny = Convert.ToInt32(key?.GetValue("fDenyTSConnections") ?? 1);
            if (deny == 1)
                return Item("rdp", "Network", "Remote Desktop (RDP) Attack Surface", "Passed", "Disabled (Closed)", "Minimal remote attack surface.");

            using var tcp = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp");
            int nla = Convert.ToInt32(tcp?.GetValue("UserAuthentication") ?? 0);
            return nla == 1
                ? Item("rdp", "Network", "Remote Desktop (RDP) Attack Surface", "Warning", "Enabled (with NLA required)", "Disable RDP if unused, or restrict TCP 3389 to VPN/trusted IPs.")
                : Item("rdp", "Network", "Remote Desktop (RDP) Attack Surface", "Failed", "Enabled WITHOUT Network Level Authentication (NLA)", "Enable NLA or disable Remote Desktop immediately.");
        }
        catch (Exception ex) { return Unavailable("rdp", "Network", "Remote Desktop (RDP) Attack Surface", ex.Message); }
    }

    [SupportedOSPlatform("windows")]
    private static HardeningCheckItem CheckControlledFolderAccess()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access");
            int mode = Convert.ToInt32(key?.GetValue("EnableControlledFolderAccess") ?? 0);
            return mode switch
            {
                1 => Item("cfa", "Ransomware", "Defender Controlled Folder Access", "Passed", "Enabled (Blocking Mode)", "Protected folders guarded against untrusted encryption."),
                2 => Item("cfa", "Ransomware", "Defender Controlled Folder Access", "Warning", "Audit Mode Only", "Switch Controlled Folder Access to Enabled in Ransomware Defense."),
                _ => Item("cfa", "Ransomware", "Defender Controlled Folder Access", "Warning", "Disabled", "Enable Controlled Folder Access or BECETTI Ransomware Canary Guard.")
            };
        }
        catch (Exception ex) { return Unavailable("cfa", "Ransomware", "Defender Controlled Folder Access", ex.Message); }
    }

    [SupportedOSPlatform("windows")]
    private static HardeningCheckItem CheckWindowsFirewallProfiles()
    {
        try
        {
            string[] profiles =
            {
                @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile",
                @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile",
                @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile"
            };
            int active = 0;
            foreach (var p in profiles)
            {
                using var key = Registry.LocalMachine.OpenSubKey(p);
                if (Convert.ToInt32(key?.GetValue("EnableFirewall") ?? 0) == 1)
                    active++;
            }
            return active == 3
                ? Item("fw", "Network", "Windows Defender Firewall Profiles", "Passed", "All 3 profiles active (Domain, Private, Public)", "Keep all firewall profiles enabled.")
                : active > 0
                    ? Item("fw", "Network", "Windows Defender Firewall Profiles", "Warning", $"{active}/3 profiles active", "Enable Firewall on all network profiles.")
                    : Item("fw", "Network", "Windows Defender Firewall Profiles", "Failed", "All firewall profiles disabled", "Enable Windows Firewall immediately.");
        }
        catch (Exception ex) { return Unavailable("fw", "Network", "Windows Defender Firewall Profiles", ex.Message); }
    }

    [SupportedOSPlatform("windows")]
    private static HardeningCheckItem CheckTpmService()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\TPM");
            if (key is null)
                return Item("tpm", "Hardware", "Trusted Platform Module (TPM)", "Warning", "TPM driver key not present", "Enable TPM 2.0 / fTPM in BIOS/UEFI if available.");
            int start = Convert.ToInt32(key.GetValue("Start") ?? 4);
            return start <= 3
                ? Item("tpm", "Hardware", "Trusted Platform Module (TPM)", "Passed", "TPM driver active", "Hardware security module ready for BitLocker & Windows Hello.")
                : Item("tpm", "Hardware", "Trusted Platform Module (TPM)", "Warning", "TPM driver disabled", "Enable TPM in firmware settings.");
        }
        catch (Exception ex) { return Unavailable("tpm", "Hardware", "Trusted Platform Module (TPM)", ex.Message); }
    }

    private static async Task<HardeningCheckItem> CheckBitLockerAsync(CancellationToken ct)
    {
        try
        {
            var sysDrive = Path.GetPathRoot(Environment.SystemDirectory)?.TrimEnd('\\') ?? "C:";
            var psi = new ProcessStartInfo
            {
                FileName = "manage-bde.exe",
                Arguments = $"-status {sysDrive}",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };
            using var proc = Process.Start(psi);
            if (proc is null)
                return Unavailable("bitlocker", "Storage", "BitLocker Disk Encryption", "manage-bde unavailable.");

            var stdout = await proc.StandardOutput.ReadToEndAsync(ct).ConfigureAwait(false);
            await proc.WaitForExitAsync(ct).ConfigureAwait(false);

            if (stdout.Contains("Protection On", StringComparison.OrdinalIgnoreCase) ||
                stdout.Contains("Fully Encrypted", StringComparison.OrdinalIgnoreCase))
            {
                return Item("bitlocker", "Storage", $"BitLocker Encryption ({sysDrive})", "Passed", "Protection On / Encrypted", "System drive data is encrypted at rest.");
            }
            if (stdout.Contains("Protection Off", StringComparison.OrdinalIgnoreCase) ||
                stdout.Contains("Fully Decrypted", StringComparison.OrdinalIgnoreCase))
            {
                return Item("bitlocker", "Storage", $"BitLocker Encryption ({sysDrive})", "Warning", "Not encrypted / Protection Off", "Enable BitLocker or Device Encryption in Windows Settings.");
            }

            return Item("bitlocker", "Storage", $"BitLocker Encryption ({sysDrive})", "Unavailable", "Requires Administrator to query BitLocker status", "Run as Administrator or check Windows Settings -> Privacy & Security -> Device Encryption.");
        }
        catch (Exception ex)
        {
            return Unavailable("bitlocker", "Storage", "BitLocker Disk Encryption", ex.Message);
        }
    }

    private static HardeningCheckItem Item(string id, string category, string title, string status, string current, string rec) =>
        new() { Id = id, Category = category, Title = title, Status = status, CurrentValue = current, Recommendation = rec };

    private static HardeningCheckItem Unavailable(string id, string category, string title, string reason) =>
        new() { Id = id, Category = category, Title = title, Status = "Unavailable", CurrentValue = reason, Recommendation = "Verify manually in Windows Security." };
}
