using System.Diagnostics;
using System.Runtime.Versioning;
using Becetti.Security.Core.Models;
using Microsoft.Win32;

namespace Becetti.Security.Core.Services;

public interface IWindowsHardeningService
{
    Task<OperationResult<WindowsHardeningReport>> AuditAsync(CancellationToken ct = default);
    Task<OperationResult<string>> RemediateCheckAsync(string checkId, bool createRestorePoint = false, CancellationToken ct = default);
}

/// <summary>
/// Real Windows Hardening &amp; Attack Surface Auditor + 1-Click Remediation Engine:
/// verifies live OS &amp; hardware security posture from Windows Registry and system tools:
/// UAC, UEFI Secure Boot, Core Isolation (HVCI Memory Integrity), SMBv1 disabled,
/// RDP exposure &amp; NLA, TPM 2.0 readiness, BitLocker drive encryption,
/// Controlled Folder Access, and Windows Firewall profiles — with real 1-click fixes.
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
            if (!OperatingSystem.IsWindows())
                return;
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

    public async Task<OperationResult<string>> RemediateCheckAsync(
        string checkId,
        bool createRestorePoint = false,
        CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
            return OperationResult<string>.Fail("Windows Hardening Remediation requires Windows.", "UNSUPPORTED_OS");

        if (string.IsNullOrWhiteSpace(checkId))
            return OperationResult<string>.Fail("Check ID is required.", "INVALID_CHECK");

        string restoreNote = string.Empty;
        if (createRestorePoint)
        {
            var rp = await RunProcessAsync(
                "powershell.exe",
                "-NoProfile -NonInteractive -Command \"Checkpoint-Computer -Description 'BECETTI SECURITY Hardening' -RestorePointType MODIFY_SETTINGS\"",
                ct).ConfigureAwait(false);
            restoreNote = rp.ExitCode == 0
                ? " System Restore Point created."
                : " (Restore Point skipped — requires System Protection enabled & Administrator).";
        }

        try
        {
            switch (checkId.Trim().ToLowerInvariant())
            {
                case "uac":
                {
                    using var key = Registry.LocalMachine.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", writable: true);
                    if (key is null)
                        return OperationResult<string>.Fail("Unable to open UAC registry key. Run as Administrator.", "ADMIN_REQUIRED");
                    key.SetValue("EnableLUA", 1, RegistryValueKind.DWord);
                    key.SetValue("ConsentPromptBehaviorAdmin", 5, RegistryValueKind.DWord);
                    return OperationResult<string>.Ok("UAC Enabled", "Enabled UAC with admin consent prompts (reboot may be required to take full effect)." + restoreNote);
                }
                case "smbv1":
                {
                    using var key = Registry.LocalMachine.OpenSubKey("SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters", writable: true);
                    if (key is null)
                        return OperationResult<string>.Fail("Unable to open LanmanServer key. Run as Administrator.", "ADMIN_REQUIRED");
                    key.SetValue("SMB1", 0, RegistryValueKind.DWord);
                    _ = await RunProcessAsync(
                        "powershell.exe",
                        "-NoProfile -NonInteractive -Command \"Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue\"",
                        ct).ConfigureAwait(false);
                    return OperationResult<string>.Ok("SMBv1 Disabled", "Disabled SMBv1 protocol in Registry and Windows Features." + restoreNote);
                }
                case "rdp":
                {
                    using var tcp = Registry.LocalMachine.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp", writable: true);
                    if (tcp is null)
                        return OperationResult<string>.Fail("Unable to open RDP-Tcp registry key. Run as Administrator.", "ADMIN_REQUIRED");
                    tcp.SetValue("UserAuthentication", 1, RegistryValueKind.DWord);
                    return OperationResult<string>.Ok("RDP NLA Enforced", "Enforced Network Level Authentication (NLA) on Remote Desktop." + restoreNote);
                }
                case "cfa":
                {
                    var res = await RunProcessAsync(
                        "powershell.exe",
                        "-NoProfile -NonInteractive -Command \"Set-MpPreference -EnableControlledFolderAccess Enabled\"",
                        ct).ConfigureAwait(false);
                    if (res.ExitCode != 0)
                        return OperationResult<string>.Fail($"Controlled Folder Access remediation requires Administrator privileges. {res.StdErr}".Trim(), "ADMIN_REQUIRED");
                    return OperationResult<string>.Ok("CFA Enabled", "Enabled Windows Defender Controlled Folder Access (Blocking Mode)." + restoreNote);
                }
                case "fw":
                {
                    var res = await RunProcessAsync("netsh.exe", "advfirewall set allprofiles state on", ct).ConfigureAwait(false);
                    if (res.ExitCode != 0)
                        return OperationResult<string>.Fail($"Firewall remediation requires Administrator privileges. {res.StdErr}".Trim(), "ADMIN_REQUIRED");
                    return OperationResult<string>.Ok("Firewall Enabled", "Enabled Windows Defender Firewall on Domain, Private, and Public profiles." + restoreNote);
                }
                default:
                    return OperationResult<string>.Fail(
                        $"Check '{checkId}' requires manual firmware/OS configuration (e.g., BIOS Secure Boot, TPM, or BitLocker wizard).",
                        "MANUAL_ONLY");
            }
        }
        catch (UnauthorizedAccessException)
        {
            return OperationResult<string>.Fail("Administrator privileges are required to apply this Windows Hardening fix.", "ADMIN_REQUIRED");
        }
        catch (Exception ex)
        {
            return OperationResult<string>.Fail($"Hardening remediation failed: {ex.Message}", "REMEDIATION_ERROR");
        }
    }

    [SupportedOSPlatform("windows")]
    private static HardeningCheckItem CheckUac()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System");
            int lua = Convert.ToInt32(key?.GetValue("EnableLUA") ?? 0);
            int prompt = Convert.ToInt32(key?.GetValue("ConsentPromptBehaviorAdmin") ?? 0);
            if (lua == 1 && prompt > 0)
                return Item("uac", "Privilege", "User Account Control (UAC)", "Passed", "Enabled with admin consent prompt", "Keep UAC enabled.", false);
            if (lua == 1)
                return Item("uac", "Privilege", "User Account Control (UAC)", "Warning", "Enabled but set to auto-elevate silently", "Set UAC to 'Notify me when apps try to make changes'.", true, "Enable UAC Prompt");
            return Item("uac", "Privilege", "User Account Control (UAC)", "Failed", "Disabled (EnableLUA=0)", "Enable UAC immediately to block silent privilege escalation.", true, "Enable UAC");
        }
        catch (Exception ex) { return Unavailable("uac", "Privilege", "User Account Control (UAC)", ex.Message); }
    }

    [SupportedOSPlatform("windows")]
    private static HardeningCheckItem CheckSecureBoot()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State");
            var val = key?.GetValue("UEFISecureBootEnabled");
            if (val is null)
                return Item("secureboot", "Firmware", "UEFI Secure Boot", "Warning", "Not reported (Legacy BIOS or VM firmware)", "Enable UEFI Secure Boot in BIOS/UEFI firmware if supported.", false);
            int enabled = Convert.ToInt32(val);
            return enabled == 1
                ? Item("secureboot", "Firmware", "UEFI Secure Boot", "Passed", "Enabled", "Verified firmware boot integrity active.", false)
                : Item("secureboot", "Firmware", "UEFI Secure Boot", "Failed", "Disabled", "Enable Secure Boot in UEFI settings to block bootkits.", false);
        }
        catch (Exception ex) { return Unavailable("secureboot", "Firmware", "UEFI Secure Boot", ex.Message); }
    }

    [SupportedOSPlatform("windows")]
    private static HardeningCheckItem CheckCoreIsolationHvci()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity");
            int enabled = Convert.ToInt32(key?.GetValue("Enabled") ?? 0);
            return enabled == 1
                ? Item("hvci", "Kernel", "Core Isolation (Memory Integrity / HVCI)", "Passed", "Enabled", "Kernel code integrity is hardware-protected.", false)
                : Item("hvci", "Kernel", "Core Isolation (Memory Integrity / HVCI)", "Warning", "Disabled", "Enable Memory Integrity in Windows Security -> Device Security -> Core Isolation.", false);
        }
        catch (Exception ex) { return Unavailable("hvci", "Kernel", "Core Isolation (Memory Integrity / HVCI)", ex.Message); }
    }

    [SupportedOSPlatform("windows")]
    private static HardeningCheckItem CheckSmbV1()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey("SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters");
            var val = key?.GetValue("SMB1");
            int smb1 = val is null ? 0 : Convert.ToInt32(val);
            return smb1 == 0
                ? Item("smbv1", "Network", "SMBv1 Legacy Protocol Disabled", "Passed", "Disabled", "Protected against WannaCry / EternalBlue SMBv1 exploits.", false)
                : Item("smbv1", "Network", "SMBv1 Legacy Protocol Disabled", "Failed", "Enabled (SMB1=1)", "Disable SMBv1 immediately to eliminate EternalBlue risk.", true, "Disable SMBv1");
        }
        catch (Exception ex) { return Unavailable("smbv1", "Network", "SMBv1 Legacy Protocol Disabled", ex.Message); }
    }

    [SupportedOSPlatform("windows")]
    private static HardeningCheckItem CheckRdpExposure()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\Terminal Server");
            int deny = Convert.ToInt32(key?.GetValue("fDenyTSConnections") ?? 1);
            if (deny == 1)
                return Item("rdp", "Network", "Remote Desktop (RDP) Attack Surface", "Passed", "Disabled (Closed)", "Minimal remote attack surface.", false);

            using var tcp = Registry.LocalMachine.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp");
            int nla = Convert.ToInt32(tcp?.GetValue("UserAuthentication") ?? 0);
            return nla == 1
                ? Item("rdp", "Network", "Remote Desktop (RDP) Attack Surface", "Warning", "Enabled (with NLA required)", "Disable RDP if unused, or restrict TCP 3389 to VPN/trusted IPs.", false)
                : Item("rdp", "Network", "Remote Desktop (RDP) Attack Surface", "Failed", "Enabled WITHOUT Network Level Authentication (NLA)", "Enable NLA or disable Remote Desktop immediately.", true, "Enforce RDP NLA");
        }
        catch (Exception ex) { return Unavailable("rdp", "Network", "Remote Desktop (RDP) Attack Surface", ex.Message); }
    }

    [SupportedOSPlatform("windows")]
    private static HardeningCheckItem CheckControlledFolderAccess()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey("SOFTWARE\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\Controlled Folder Access");
            int mode = Convert.ToInt32(key?.GetValue("EnableControlledFolderAccess") ?? 0);
            return mode switch
            {
                1 => Item("cfa", "Ransomware", "Defender Controlled Folder Access", "Passed", "Enabled (Blocking Mode)", "Protected folders guarded against untrusted encryption.", false),
                2 => Item("cfa", "Ransomware", "Defender Controlled Folder Access", "Warning", "Audit Mode Only", "Switch Controlled Folder Access to Enabled in Ransomware Defense.", true, "Enable CFA"),
                _ => Item("cfa", "Ransomware", "Defender Controlled Folder Access", "Warning", "Disabled", "Enable Controlled Folder Access or BECETTI Ransomware Canary Guard.", true, "Enable CFA")
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
                "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\DomainProfile",
                "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile",
                "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\PublicProfile"
            };
            int active = 0;
            foreach (var p in profiles)
            {
                using var key = Registry.LocalMachine.OpenSubKey(p);
                if (Convert.ToInt32(key?.GetValue("EnableFirewall") ?? 0) == 1)
                    active++;
            }
            return active == 3
                ? Item("fw", "Network", "Windows Defender Firewall Profiles", "Passed", "All 3 profiles active (Domain, Private, Public)", "Keep all firewall profiles enabled.", false)
                : active > 0
                    ? Item("fw", "Network", "Windows Defender Firewall Profiles", "Warning", $"{active}/3 profiles active", "Enable Firewall on all network profiles.", true, "Enable All Profiles")
                    : Item("fw", "Network", "Windows Defender Firewall Profiles", "Failed", "All firewall profiles disabled", "Enable Windows Firewall immediately.", true, "Enable Firewall");
        }
        catch (Exception ex) { return Unavailable("fw", "Network", "Windows Defender Firewall Profiles", ex.Message); }
    }

    [SupportedOSPlatform("windows")]
    private static HardeningCheckItem CheckTpmService()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey("SYSTEM\\CurrentControlSet\\Services\\TPM");
            if (key is null)
                return Item("tpm", "Hardware", "Trusted Platform Module (TPM)", "Warning", "TPM driver key not present", "Enable TPM 2.0 / fTPM in BIOS/UEFI if available.", false);
            int start = Convert.ToInt32(key.GetValue("Start") ?? 4);
            return start <= 3
                ? Item("tpm", "Hardware", "Trusted Platform Module (TPM)", "Passed", "TPM driver active", "Hardware security module ready for BitLocker & Windows Hello.", false)
                : Item("tpm", "Hardware", "Trusted Platform Module (TPM)", "Warning", "TPM driver disabled", "Enable TPM in firmware settings.", false);
        }
        catch (Exception ex) { return Unavailable("tpm", "Hardware", "Trusted Platform Module (TPM)", ex.Message); }
    }

    private static async Task<HardeningCheckItem> CheckBitLockerAsync(CancellationToken ct)
    {
        try
        {
            var sysDrive = Path.GetPathRoot(Environment.SystemDirectory)?.TrimEnd('\\') ?? "C:";
            var res = await RunProcessAsync("manage-bde.exe", $"-status {sysDrive}", ct).ConfigureAwait(false);
            var stdout = res.StdOut;

            if (stdout.Contains("Protection On", StringComparison.OrdinalIgnoreCase) ||
                stdout.Contains("Fully Encrypted", StringComparison.OrdinalIgnoreCase))
            {
                return Item("bitlocker", "Storage", $"BitLocker Encryption ({sysDrive})", "Passed", "Protection On / Encrypted", "System drive data is encrypted at rest.", false);
            }
            if (stdout.Contains("Protection Off", StringComparison.OrdinalIgnoreCase) ||
                stdout.Contains("Fully Decrypted", StringComparison.OrdinalIgnoreCase))
            {
                return Item("bitlocker", "Storage", $"BitLocker Encryption ({sysDrive})", "Warning", "Not encrypted / Protection Off", "Enable BitLocker or Device Encryption in Windows Settings.", false);
            }

            return Item("bitlocker", "Storage", $"BitLocker Encryption ({sysDrive})", "Unavailable", "Requires Administrator to query BitLocker status", "Run as Administrator or check Windows Settings -> Privacy & Security -> Device Encryption.", false);
        }
        catch (Exception ex)
        {
            return Unavailable("bitlocker", "Storage", "BitLocker Disk Encryption", ex.Message);
        }
    }

    private static async Task<(int ExitCode, string StdOut, string StdErr)> RunProcessAsync(string fileName, string args, CancellationToken ct)
    {
        var psi = new ProcessStartInfo
        {
            FileName = fileName,
            Arguments = args,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        using var proc = Process.Start(psi);
        if (proc is null)
            return (-1, string.Empty, $"Failed to start {fileName}");
        var outTask = proc.StandardOutput.ReadToEndAsync(ct);
        var errTask = proc.StandardError.ReadToEndAsync(ct);
        await proc.WaitForExitAsync(ct).ConfigureAwait(false);
        return (proc.ExitCode, await outTask.ConfigureAwait(false), await errTask.ConfigureAwait(false));
    }

    private static HardeningCheckItem Item(
        string id,
        string category,
        string title,
        string status,
        string current,
        string rec,
        bool canAutoFix,
        string autoFixAction = "") =>
        new()
        {
            Id = id,
            Category = category,
            Title = title,
            Status = status,
            CurrentValue = current,
            Recommendation = rec,
            CanAutoFix = canAutoFix,
            AutoFixAction = autoFixAction
        };

    private static HardeningCheckItem Unavailable(string id, string category, string title, string reason) =>
        new()
        {
            Id = id,
            Category = category,
            Title = title,
            Status = "Unavailable",
            CurrentValue = reason,
            Recommendation = "Verify manually in Windows Security.",
            CanAutoFix = false
        };
}
