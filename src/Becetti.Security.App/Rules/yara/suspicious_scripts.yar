/*
 * Suspicious Script & Ransomware Recovery-Tampering Indicators
 * Standard YARA 4.x rules with zero external module dependencies.
 */

rule Suspicious_PowerShell_Download_Cradle : script powershell dropper
{
    meta:
        description = "Detects PowerShell scripts combining hidden execution or encoded commands with remote download-and-execute cradles"
        author = "BECETTI SECURITY"
        severity = "High"
        category = "Dropper"
        reference = "https://attack.mitre.org/techniques/T1059/001/"
        date = "2026-11-22"

    strings:
        $ps1 = "powershell" ascii wide nocase
        $enc1 = "-EncodedCommand" ascii wide nocase
        $enc2 = "-enc " ascii wide nocase
        $hid = "-WindowStyle Hidden" ascii wide nocase
        $byp = "-ExecutionPolicy Bypass" ascii wide nocase
        $dl1 = "Net.WebClient" ascii wide nocase
        $dl2 = "DownloadString" ascii wide nocase
        $dl3 = "DownloadFile" ascii wide nocase
        $dl4 = "Invoke-WebRequest" ascii wide nocase
        $exec1 = "Invoke-Expression" ascii wide nocase
        $exec2 = "IEX(" ascii wide nocase
        $exec3 = "IEX (" ascii wide nocase

    condition:
        filesize < 2MB and
        $ps1 and
        (1 of ($enc1, $enc2, $hid, $byp)) and
        (1 of ($dl1, $dl2, $dl3, $dl4)) and
        (1 of ($exec1, $exec2, $exec3))
}

rule Ransomware_ShadowCopy_Deletion_Command : ransomware impact
{
    meta:
        description = "Detects scripts or binaries containing commands commonly used by ransomware to delete Windows Volume Shadow Copies and disable recovery"
        author = "BECETTI SECURITY"
        severity = "Critical"
        category = "Ransomware"
        reference = "https://attack.mitre.org/techniques/T1490/"
        date = "2026-11-22"

    strings:
        $vss1 = "vssadmin delete shadows" ascii wide nocase
        $vss2 = "vssadmin.exe delete shadows" ascii wide nocase
        $wmic = "wmic shadowcopy delete" ascii wide nocase
        $wbadmin = "wbadmin delete catalog" ascii wide nocase
        $bcd1 = "bcdedit /set {default} recoveryenabled no" ascii wide nocase
        $bcd2 = "bcdedit /set {default} bootstatuspolicy ignoreallfailures" ascii wide nocase

    condition:
        filesize < 10MB and
        (
            ($vss1 or $vss2 or $wmic) and
            ($wbadmin or $bcd1 or $bcd2)
        )
}

rule Suspicious_MSHTA_Or_Certutil_Dropper : script lolbin dropper
{
    meta:
        description = "Detects suspicious scripts leveraging certutil URL cache download combined with script execution or mshta remote payload execution"
        author = "BECETTI SECURITY"
        severity = "High"
        category = "Dropper"
        reference = "https://attack.mitre.org/techniques/T1218/005/"
        date = "2026-11-22"

    strings:
        $cert1 = "certutil" ascii wide nocase
        $cert2 = "-urlcache" ascii wide nocase
        $cert3 = "-split" ascii wide nocase
        $cert4 = "-f http" ascii wide nocase
        $mshta1 = "mshta.exe http" ascii wide nocase
        $mshta2 = "mshta http" ascii wide nocase
        $vb = "vbscript:Execute" ascii wide nocase
        $js = "javascript:a=GetObject" ascii wide nocase

    condition:
        filesize < 2MB and
        (
            ($cert1 and $cert2 and ($cert3 or $cert4)) or
            (($mshta1 or $mshta2) and ($vb or $js))
        )
}
