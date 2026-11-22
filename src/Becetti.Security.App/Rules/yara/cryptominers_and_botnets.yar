/*
 * BECETTI SECURITY — Cryptominers, Wallet Clippers, Botnets & USB Worms
 * Standard YARA 4.x compatible · Mapped to MITRE ATT&CK Enterprise
 */

rule Cryptominer_XMRig_Stratum_Config : cryptominer
{
    meta:
        description = "Detects unauthorized cryptocurrency miners (XMRig / RandomX / Stratum protocol binaries or configs)"
        author = "BECETTI SECURITY"
        severity = "High"
        category = "Cryptominer"
        mitre = "T1496"
        reference = "https://attack.mitre.org/techniques/T1496/"
        date = "2026-11-22"

    strings:
        $s1 = "stratum+tcp://" ascii wide nocase
        $s2 = "stratum+ssl://" ascii wide nocase
        $a1 = "randomx" ascii wide nocase
        $a2 = "cryptonight" ascii wide nocase
        $a3 = "rx/0" ascii wide nocase
        $a4 = "donate-level" ascii wide nocase
        $a5 = "xmrig" ascii wide nocase

    condition:
        filesize < 25MB and
        (1 of ($s*)) and
        (2 of ($a*))
}

rule Cryptominer_Mining_Pool_Endpoints : cryptominer
{
    meta:
        description = "Detects scripts or executables configured with public Monero/Ethereum mining pools and worker flags"
        author = "BECETTI SECURITY"
        severity = "Medium"
        category = "Cryptominer"
        mitre = "T1496"
        reference = "https://attack.mitre.org/techniques/T1496/"
        date = "2026-11-22"

    strings:
        $p1 = "pool.minexmr.com" ascii wide nocase
        $p2 = "pool.supportxmr.com" ascii wide nocase
        $p3 = "xmrpool.eu" ascii wide nocase
        $p4 = "pool.hashvault.pro" ascii wide nocase
        $p5 = "nanopool.org" ascii wide nocase
        $p6 = "2miners.com" ascii wide nocase
        $f1 = "--donate-level" ascii wide nocase
        $f2 = "--algo=" ascii wide nocase
        $f3 = "-o stratum" ascii wide nocase
        $f4 = "--user=" ascii wide nocase

    condition:
        filesize < 20MB and
        (1 of ($p*)) and
        (1 of ($f*))
}

rule Cryptominer_Clipboard_Wallet_Clipper : clipper crypto
{
    meta:
        description = "Detects clipboard hijackers that silently replace copied Bitcoin/Ethereum/Tron wallet addresses"
        author = "BECETTI SECURITY"
        severity = "Critical"
        category = "Clipper"
        mitre = "T1115"
        reference = "https://attack.mitre.org/techniques/T1115/"
        date = "2026-11-22"

    strings:
        $c1 = "OpenClipboard" ascii wide
        $c2 = "GetClipboardData" ascii wide
        $c3 = "SetClipboardData" ascii wide
        $r1 = "^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}$" ascii wide
        $r2 = "^0x[a-fA-F0-9]{40}$" ascii wide
        $r3 = "^4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}$" ascii wide
        $r4 = "^T[A-Za-z1-9]{33}$" ascii wide

    condition:
        filesize < 15MB and
        ($c1 and $c2 and $c3) and
        (1 of ($r*))
}

rule Botnet_DDoS_Flooder_Indicators : botnet ddos
{
    meta:
        description = "Detects DDoS botnet clients supporting UDP/SYN/HTTP flood attack commands"
        author = "BECETTI SECURITY"
        severity = "High"
        category = "Botnet"
        mitre = "T1498"
        reference = "https://attack.mitre.org/techniques/T1498/"
        date = "2026-11-22"

    strings:
        $d1 = "UDPFLOOD" ascii wide nocase
        $d2 = "SYNFLOOD" ascii wide nocase
        $d3 = "HTTPFLOOD" ascii wide nocase
        $d4 = "SLOWLORIS" ascii wide nocase
        $d5 = "ACKFLOOD" ascii wide nocase
        $n1 = "socket" ascii wide nocase
        $n2 = "sendto" ascii wide nocase

    condition:
        filesize < 15MB and
        (2 of ($d*)) and
        (1 of ($n*))
}

rule Worm_USB_Autorun_Spreader : worm usb
{
    meta:
        description = "Detects removable-media worms that enumerate USB drives, hide user folders, and drop autorun/LNK payloads"
        author = "BECETTI SECURITY"
        severity = "High"
        category = "Worm"
        mitre = "T1091"
        reference = "https://attack.mitre.org/techniques/T1091/"
        date = "2026-11-22"

    strings:
        $u1 = "GetDriveType" ascii wide
        $u2 = "GetLogicalDriveStrings" ascii wide
        $a1 = "autorun.inf" ascii wide nocase
        $a2 = "shellexecute=" ascii wide nocase
        $h1 = "attrib +h +s" ascii wide nocase
        $h2 = "WScript.Shell" ascii wide nocase
        $h3 = "CreateShortcut" ascii wide nocase

    condition:
        filesize < 15MB and
        (($u1 or $u2) and $a1 and ($a2 or $h1)) or
        ($h1 and $h2 and $h3 and $a1)
}
