/*
 * BECETTI SECURITY — Ransomware Behavior & Extortion Detection Rules
 * Standard YARA 4.x compatible · Mapped to MITRE ATT&CK Enterprise
 */

rule Ransomware_Recovery_Inhibition_Commands : ransomware impact
{
    meta:
        description = "Detects commands that disable Windows Recovery, delete Volume Shadow Copies, or wipe backup catalogs"
        author = "BECETTI SECURITY"
        severity = "Critical"
        category = "Ransomware"
        mitre = "T1490"
        reference = "https://attack.mitre.org/techniques/T1490/"
        date = "2026-11-22"

    strings:
        $vss1 = "vssadmin delete shadows" ascii wide nocase
        $vss2 = "wmic shadowcopy delete" ascii wide nocase
        $vss3 = "Win32_ShadowCopy" ascii wide nocase
        $bcd1 = "bcdedit /set {default} recoveryenabled no" ascii wide nocase
        $bcd2 = "bcdedit /set {default} bootstatuspolicy ignoreallfailures" ascii wide nocase
        $wb1  = "wbadmin delete catalog" ascii wide nocase
        $wb2  = "wbadmin delete systemstatebackup" ascii wide nocase
        $ps1  = "Get-WmiObject Win32_ShadowCopy" ascii wide nocase

    condition:
        filesize < 15MB and
        (2 of ($vss*, $bcd*, $wb*, $ps*))
}

rule Ransomware_Ransom_Note_Extortion_Strings : ransomware extortion
{
    meta:
        description = "Detects ransomware extortion notes demanding cryptocurrency payment and Tor decryptor contact"
        author = "BECETTI SECURITY"
        severity = "High"
        category = "Ransomware"
        mitre = "T1486"
        reference = "https://attack.mitre.org/techniques/T1486/"
        date = "2026-11-22"

    strings:
        $enc1 = "all your files have been encrypted" ascii wide nocase
        $enc2 = "your files are encrypted" ascii wide nocase
        $enc3 = "your network has been penetrated" ascii wide nocase
        $pay1 = "bitcoin" ascii wide nocase
        $pay2 = "monero" ascii wide nocase
        $pay3 = "decryptor" ascii wide nocase
        $pay4 = "decryption key" ascii wide nocase
        $tor1 = ".onion" ascii wide nocase
        $tor2 = "torproject.org" ascii wide nocase
        $warn = "do not rename" ascii wide nocase

    condition:
        filesize < 2MB and
        (1 of ($enc*)) and
        (1 of ($pay*)) and
        (1 of ($tor*, $warn))
}

rule Ransomware_Known_Family_Markers : ransomware critical
{
    meta:
        description = "Detects distinct strings associated with major ransomware families (LockBit, BlackCat/ALPHV, Conti, Akira, BlackBasta)"
        author = "BECETTI SECURITY"
        severity = "Critical"
        category = "Ransomware"
        mitre = "T1486"
        reference = "https://attack.mitre.org/techniques/T1486/"
        date = "2026-11-22"

    strings:
        $lb1 = "Restore-My-Files.txt" ascii wide nocase
        $lb2 = "LockBit Black" ascii wide nocase
        $lb3 = "LockBit 3.0" ascii wide nocase
        $bc1 = "RECOVER-" ascii wide
        $bc2 = "access-token" ascii wide nocase
        $bc3 = "--access-token" ascii wide nocase
        $ct1 = "CONTI_LOG.txt" ascii wide nocase
        $ct2 = "readme.txt" ascii wide nocase
        $ak1 = "akira_readme.txt" ascii wide nocase
        $bb1 = "BlackBasta" ascii wide nocase

    condition:
        filesize < 25MB and
        ($lb1 and ($lb2 or $lb3)) or
        ($bc1 and $bc3) or
        $ct1 or
        $ak1 or
        ($bb1 and $ct2)
}

rule Ransomware_Mass_Crypto_API_PE : ransomware pe
{
    meta:
        description = "Detects Windows PE combining file-tree enumeration with CryptoAPI encryption and shadow-copy inhibition"
        author = "BECETTI SECURITY"
        severity = "Critical"
        category = "Ransomware"
        mitre = "T1486"
        reference = "https://attack.mitre.org/techniques/T1486/"
        date = "2026-11-22"

    strings:
        $c1 = "CryptAcquireContext" ascii wide
        $c2 = "CryptGenRandom" ascii wide
        $c3 = "CryptEncrypt" ascii wide
        $f1 = "FindFirstFileW" ascii wide
        $f2 = "FindNextFileW" ascii wide
        $f3 = "MoveFileExW" ascii wide
        $k1 = "vssadmin" ascii wide nocase
        $k2 = "bcdedit" ascii wide nocase
        $k3 = "wbadmin" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        filesize < 20MB and
        (2 of ($c*)) and
        (2 of ($f*)) and
        (1 of ($k*))
}

rule Ransomware_Service_Termination_Script : ransomware impact
{
    meta:
        description = "Detects scripts mass-stopping database, backup, and security services prior to file encryption"
        author = "BECETTI SECURITY"
        severity = "High"
        category = "Ransomware"
        mitre = "T1489"
        reference = "https://attack.mitre.org/techniques/T1489/"
        date = "2026-11-22"

    strings:
        $cmd1 = "net stop" ascii wide nocase
        $cmd2 = "taskkill /f /im" ascii wide nocase
        $cmd3 = "sc stop" ascii wide nocase
        $svc1 = "vss" ascii wide nocase
        $svc2 = "sql" ascii wide nocase
        $svc3 = "veeam" ascii wide nocase
        $svc4 = "memtas" ascii wide nocase
        $svc5 = "mepocs" ascii wide nocase
        $svc6 = "backupexec" ascii wide nocase
        $svc7 = "sophos" ascii wide nocase

    condition:
        filesize < 5MB and
        (1 of ($cmd*)) and
        (4 of ($svc*))
}

rule Ransomware_Wallpaper_Hijack_And_Note_Drop : ransomware impact
{
    meta:
        description = "Detects binaries combining desktop wallpaper modification with ransom note creation"
        author = "BECETTI SECURITY"
        severity = "High"
        category = "Ransomware"
        mitre = "T1491.001"
        reference = "https://attack.mitre.org/techniques/T1491/001/"
        date = "2026-11-22"

    strings:
        $wp1 = "SystemParametersInfo" ascii wide
        $wp2 = "Control Panel\\Desktop" ascii wide nocase
        $wp3 = "Wallpaper" ascii wide nocase
        $rn1 = "README_FOR_DECRYPT" ascii wide nocase
        $rn2 = "HOW_TO_RECOVER" ascii wide nocase
        $rn3 = "DECRYPT_INSTRUCTIONS" ascii wide nocase
        $rn4 = "HOW_TO_DECRYPT" ascii wide nocase

    condition:
        filesize < 20MB and
        ($wp1 or ($wp2 and $wp3)) and
        (1 of ($rn*))
}
