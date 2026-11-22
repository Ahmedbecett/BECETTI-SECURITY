/*
 * BECETTI SECURITY — Infostealer, Browser Vault & Credential Theft Rules
 * Standard YARA 4.x compatible · Mapped to MITRE ATT&CK Enterprise
 */

rule Infostealer_Chromium_Browser_Vault_Access : stealer browser
{
    meta:
        description = "Detects infostealers extracting DPAPI-protected Chromium browser passwords and cookies"
        author = "BECETTI SECURITY"
        severity = "Critical"
        category = "Infostealer"
        mitre = "T1555.003"
        reference = "https://attack.mitre.org/techniques/T1555/003/"
        date = "2026-11-22"

    strings:
        $p1 = "User Data\\Default\\Login Data" ascii wide nocase
        $p2 = "User Data\\Local State" ascii wide nocase
        $p3 = "encrypted_key" ascii wide
        $p4 = "CryptUnprotectData" ascii wide
        $p5 = "SELECT origin_url, username_value, password_value FROM logins" ascii wide nocase
        $p6 = "os_crypt" ascii wide

    condition:
        filesize < 20MB and
        ($p4 and ($p1 or $p5) and ($p2 or $p3 or $p6))
}

rule Infostealer_Firefox_Credential_Harvesting : stealer browser
{
    meta:
        description = "Detects tools harvesting Mozilla Firefox password stores (logins.json, key4.db, NSS decryption)"
        author = "BECETTI SECURITY"
        severity = "High"
        category = "Infostealer"
        mitre = "T1555.003"
        reference = "https://attack.mitre.org/techniques/T1555/003/"
        date = "2026-11-22"

    strings:
        $f1 = "Mozilla\\Firefox\\Profiles" ascii wide nocase
        $f2 = "logins.json" ascii wide nocase
        $f3 = "key4.db" ascii wide nocase
        $f4 = "nss3.dll" ascii wide nocase
        $f5 = "PK11SDR_Decrypt" ascii wide

    condition:
        filesize < 20MB and
        ($f1 and $f2 and ($f3 or $f4 or $f5))
}

rule Infostealer_Crypto_Wallet_Exfiltration : stealer crypto
{
    meta:
        description = "Detects infostealers enumerating cryptocurrency wallet extensions and desktop wallet vaults"
        author = "BECETTI SECURITY"
        severity = "Critical"
        category = "Infostealer"
        mitre = "T1005"
        reference = "https://attack.mitre.org/techniques/T1005/"
        date = "2026-11-22"

    strings:
        $w1 = "nkbihfbeogaeaoehlefnkodbefgpgknn" ascii wide nocase
        $w2 = "bfnaelmomeimhlpmgjnjophhpkkoljpa" ascii wide nocase
        $w3 = "ejbalbakoplchlghecdalmeeeajnimhm" ascii wide nocase
        $w4 = "Exodus\\exodus.wallet" ascii wide nocase
        $w5 = "Electrum\\wallets" ascii wide nocase
        $w6 = "atomic\\Local Storage\\leveldb" ascii wide nocase
        $w7 = "wallet.dat" ascii wide nocase

    condition:
        filesize < 20MB and
        (3 of ($w*))
}

rule Infostealer_Discord_Telegram_Session_Theft : stealer token
{
    meta:
        description = "Detects Discord authentication token grabbers and Telegram tdata session stealers"
        author = "BECETTI SECURITY"
        severity = "High"
        category = "Infostealer"
        mitre = "T1528"
        reference = "https://attack.mitre.org/techniques/T1528/"
        date = "2026-11-22"

    strings:
        $d1 = "dQw4w9WgXcQ:" ascii wide
        $d2 = "discord\\Local Storage\\leveldb" ascii wide nocase
        $d3 = "discordcanary\\Local Storage\\leveldb" ascii wide nocase
        $t1 = "Telegram Desktop\\tdata" ascii wide nocase
        $t2 = "D877F783D5D3EF8C" ascii wide
        $t3 = "key_datas" ascii wide

    condition:
        filesize < 20MB and
        (($d1 and ($d2 or $d3)) or ($t1 and ($t2 or $t3)))
}

rule Infostealer_Webhook_Exfiltration_Agent : stealer exfiltration
{
    meta:
        description = "Detects stealers exfiltrating harvested passwords or cookies via Discord webhooks or Telegram bots"
        author = "BECETTI SECURITY"
        severity = "Critical"
        category = "Infostealer"
        mitre = "T1041"
        reference = "https://attack.mitre.org/techniques/T1041/"
        date = "2026-11-22"

    strings:
        $ex1 = "https://api.telegram.org/bot" ascii wide nocase
        $ex2 = "discord.com/api/webhooks/" ascii wide nocase
        $ex3 = "discordapp.com/api/webhooks/" ascii wide nocase
        $st1 = "Login Data" ascii wide nocase
        $st2 = "Cookies" ascii wide nocase
        $st3 = "Web Data" ascii wide nocase
        $st4 = "passwords.txt" ascii wide nocase
        $st5 = "CryptUnprotectData" ascii wide

    condition:
        filesize < 20MB and
        (1 of ($ex*)) and
        (2 of ($st*))
}

rule Credential_SAM_NTDS_Registry_Hive_Dump : credential_access
{
    meta:
        description = "Detects dumping of Windows SAM, SYSTEM, SECURITY registry hives or Active Directory NTDS.dit"
        author = "BECETTI SECURITY"
        severity = "Critical"
        category = "Credential-Theft"
        mitre = "T1003.002"
        reference = "https://attack.mitre.org/techniques/T1003/002/"
        date = "2026-11-22"

    strings:
        $r1 = "reg save hklm\\sam" ascii wide nocase
        $r2 = "reg save hklm\\system" ascii wide nocase
        $r3 = "reg save hklm\\security" ascii wide nocase
        $r4 = "reg.exe save HKLM\\SAM" ascii wide nocase
        $n1 = "ntdsutil" ascii wide nocase
        $n2 = "create full" ascii wide nocase
        $n3 = "ntds.dit" ascii wide nocase

    condition:
        filesize < 15MB and
        ((2 of ($r*)) or ($n1 and $n2 and $n3))
}
