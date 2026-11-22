/*
 * BECETTI SECURITY — Defense Evasion, AMSI/ETW Bypass & Persistence Rules
 * Standard YARA 4.x compatible · Mapped to MITRE ATT&CK Enterprise
 */

rule DefenseEvasion_AMSI_And_ETW_Patching : evasion amsi
{
    meta:
        description = "Detects scripts or binaries attempting to patch AmsiScanBuffer or EtwEventWrite in memory to blind security monitoring"
        author = "BECETTI SECURITY"
        severity = "Critical"
        category = "Defense-Evasion"
        mitre = "T1562.001"
        reference = "https://attack.mitre.org/techniques/T1562/001/"
        date = "2026-11-22"

    strings:
        $a1 = "AmsiScanBuffer" ascii wide
        $a2 = "amsiInitFailed" ascii wide
        $a3 = "AmsiUtils" ascii wide
        $e1 = "EtwEventWrite" ascii wide
        $p1 = "VirtualProtect" ascii wide
        $p2 = "Marshal]::Copy" ascii wide nocase

    condition:
        filesize < 15MB and
        (($a2 and $a3) or (($a1 or $e1) and ($p1 or $p2)))
}

rule DefenseEvasion_Defender_Exclusion_Tampering : evasion defender
{
    meta:
        description = "Detects malicious attempts to disable Microsoft Defender real-time protection or add broad exclusion paths"
        author = "BECETTI SECURITY"
        severity = "Critical"
        category = "Defense-Evasion"
        mitre = "T1562.001"
        reference = "https://attack.mitre.org/techniques/T1562/001/"
        date = "2026-11-22"

    strings:
        $d1 = "Set-MpPreference" ascii wide nocase
        $d2 = "Add-MpPreference" ascii wide nocase
        $f1 = "-DisableRealtimeMonitoring $true" ascii wide nocase
        $f2 = "-DisableBehaviorMonitoring $true" ascii wide nocase
        $f3 = "-DisableIOAVProtection $true" ascii wide nocase
        $f4 = "-ExclusionPath \"C:\\" ascii wide nocase
        $f5 = "-ExclusionPath 'C:\\" ascii wide nocase
        $f6 = "-ExclusionPath C:\\" ascii wide nocase
        $r1 = "DisableAntiSpyware" ascii wide nocase

    condition:
        filesize < 10MB and
        (($d1 or $d2) and (1 of ($f*))) or
        ($r1 and $d1)
}

rule DefenseEvasion_EventLog_Clearing_Tampering : evasion anti_forensics
{
    meta:
        description = "Detects scripts attempting to erase Windows Security, System, or PowerShell event logs to cover tracks"
        author = "BECETTI SECURITY"
        severity = "High"
        category = "Defense-Evasion"
        mitre = "T1070.001"
        reference = "https://attack.mitre.org/techniques/T1070/001/"
        date = "2026-11-22"

    strings:
        $w1 = "wevtutil cl Security" ascii wide nocase
        $w2 = "wevtutil cl System" ascii wide nocase
        $w3 = "wevtutil cl Application" ascii wide nocase
        $w4 = "wevtutil cl Microsoft-Windows-PowerShell" ascii wide nocase
        $p1 = "Clear-EventLog -LogName Security" ascii wide nocase
        $p2 = "GlobalSession.ClearLog" ascii wide nocase

    condition:
        filesize < 5MB and
        (2 of ($w*)) or
        $p1 or
        $p2
}

rule DefenseEvasion_UAC_Bypass_Techniques : evasion privilege_escalation
{
    meta:
        description = "Detects fileless UAC bypass techniques abusing fodhelper, eventvwr, or ms-settings registry hijack"
        author = "BECETTI SECURITY"
        severity = "High"
        category = "Privilege-Escalation"
        mitre = "T1548.002"
        reference = "https://attack.mitre.org/techniques/T1548/002/"
        date = "2026-11-22"

    strings:
        $k1 = "Software\\Classes\\ms-settings\\Shell\\Open\\command" ascii wide nocase
        $k2 = "Software\\Classes\\mscfile\\shell\\open\\command" ascii wide nocase
        $k3 = "DelegateExecute" ascii wide nocase
        $b1 = "fodhelper.exe" ascii wide nocase
        $b2 = "computerdefaults.exe" ascii wide nocase
        $b3 = "eventvwr.exe" ascii wide nocase

    condition:
        filesize < 10MB and
        (($k1 and ($k3 or $b1 or $b2)) or ($k2 and $b3))
}

rule Persistence_WMI_Event_Subscription_Script : persistence wmi
{
    meta:
        description = "Detects fileless WMI permanent event subscription persistence setup"
        author = "BECETTI SECURITY"
        severity = "High"
        category = "Persistence"
        mitre = "T1546.003"
        reference = "https://attack.mitre.org/techniques/T1546/003/"
        date = "2026-11-22"

    strings:
        $w1 = "__EventFilter" ascii wide nocase
        $w2 = "CommandLineEventConsumer" ascii wide nocase
        $w3 = "ActiveScriptEventConsumer" ascii wide nocase
        $w4 = "__FilterToConsumerBinding" ascii wide nocase

    condition:
        filesize < 10MB and
        $w1 and $w4 and ($w2 or $w3)
}

rule Persistence_IFEO_Debugger_Hijack : persistence privilege_escalation
{
    meta:
        description = "Detects Image File Execution Options (IFEO) debugger hijacking targeting accessibility binaries or security tools"
        author = "BECETTI SECURITY"
        severity = "Critical"
        category = "Persistence"
        mitre = "T1546.012"
        reference = "https://attack.mitre.org/techniques/T1546/012/"
        date = "2026-11-22"

    strings:
        $ifeo = "Image File Execution Options" ascii wide nocase
        $dbg  = "Debugger" ascii wide nocase
        $t1   = "sethc.exe" ascii wide nocase
        $t2   = "utilman.exe" ascii wide nocase
        $t3   = "osk.exe" ascii wide nocase
        $t4   = "Magnify.exe" ascii wide nocase
        $t5   = "cmd.exe" ascii wide nocase

    condition:
        filesize < 10MB and
        $ifeo and $dbg and (1 of ($t1, $t2, $t3, $t4)) and $t5
}
