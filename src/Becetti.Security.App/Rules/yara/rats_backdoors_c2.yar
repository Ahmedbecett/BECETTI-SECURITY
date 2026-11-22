/*
 * BECETTI SECURITY — RATs, Backdoors, Keyloggers & C2 Implant Rules
 * Standard YARA 4.x compatible · Mapped to MITRE ATT&CK Enterprise
 */

rule RAT_Keylogger_And_Clipboard_Hook_PE : spyware keylogger pe
{
    meta:
        description = "Detects Windows PE spyware combining low-level keyboard hooking, active window title capture, and clipboard snooping"
        author = "BECETTI SECURITY"
        severity = "High"
        category = "Spyware"
        mitre = "T1056.001"
        reference = "https://attack.mitre.org/techniques/T1056/001/"
        date = "2026-11-22"

    strings:
        $k1 = "SetWindowsHookEx" ascii wide
        $k2 = "GetAsyncKeyState" ascii wide
        $k3 = "GetKeyNameText" ascii wide
        $w1 = "GetForegroundWindow" ascii wide
        $w2 = "GetWindowText" ascii wide
        $c1 = "GetClipboardData" ascii wide
        $c2 = "AddClipboardFormatListener" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB and
        ($k1 and ($k2 or $k3) and $w1 and $w2 and ($c1 or $c2))
}

rule RAT_Screen_And_Webcam_Surveillance_PE : rat spyware pe
{
    meta:
        description = "Detects remote access trojans combining webcam capture, desktop screen grabbing, and raw network sockets"
        author = "BECETTI SECURITY"
        severity = "High"
        category = "RAT"
        mitre = "T1113"
        reference = "https://attack.mitre.org/techniques/T1113/"
        date = "2026-11-22"

    strings:
        $cam1 = "capCreateCaptureWindow" ascii wide
        $cam2 = "avicap32.dll" ascii wide nocase
        $scr1 = "CreateCompatibleBitmap" ascii wide
        $scr2 = "BitBlt" ascii wide
        $net1 = "WSAStartup" ascii wide
        $net2 = "InternetOpen" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 20MB and
        ($cam1 or $cam2) and
        ($scr1 and $scr2) and
        ($net1 or $net2)
}

rule Backdoor_CobaltStrike_Beacon_Indicators : c2 backdoor critical
{
    meta:
        description = "Detects Cobalt Strike Beacon artifacts, default SMB named pipes, and staging indicators"
        author = "BECETTI SECURITY"
        severity = "Critical"
        category = "C2-Implant"
        mitre = "T1071.001"
        reference = "https://attack.mitre.org/techniques/T1071/001/"
        date = "2026-11-22"

    strings:
        $p1 = "\\\\.\\pipe\\MSSE-" ascii wide
        $p2 = "\\\\.\\pipe\\msagent_" ascii wide
        $p3 = "\\\\.\\pipe\\postex_" ascii wide
        $s1 = "%s as %s\\%s: %d" ascii
        $s2 = "ReflectiveLoader" ascii
        $s3 = "beacon.dll" ascii nocase
        $s4 = "beacon.x64.dll" ascii nocase

    condition:
        filesize < 15MB and
        (2 of ($p*, $s*))
}

rule Backdoor_Common_Commodity_RAT_Markers : rat backdoor
{
    meta:
        description = "Detects distinct markers of commodity Windows RAT families (AsyncRAT, QuasarRAT, NjRAT, Remcos, Warzone)"
        author = "BECETTI SECURITY"
        severity = "Critical"
        category = "RAT"
        mitre = "T1219"
        reference = "https://attack.mitre.org/techniques/T1219/"
        date = "2026-11-22"

    strings:
        $r1 = "AsyncClient" ascii wide
        $r2 = "Pastebin" ascii wide
        $r3 = "Remcos_Mutex_Inj" ascii wide
        $r4 = "Breaking-Security.Net" ascii wide
        $r5 = "Quasar.Client" ascii wide
        $r6 = "njq8" ascii wide
        $r7 = "netsh firewall add allowedprogram" ascii wide nocase

    condition:
        filesize < 15MB and
        ($r3 or ($r1 and $r2) or $r5 or ($r4 and $r7) or ($r6 and $r7))
}

rule Backdoor_Meterpreter_Shellcode_Stager : backdoor c2
{
    meta:
        description = "Detects Metasploit Meterpreter DLL/payload markers and standard extension commands"
        author = "BECETTI SECURITY"
        severity = "Critical"
        category = "C2-Implant"
        mitre = "T1059"
        reference = "https://attack.mitre.org/techniques/T1059/"
        date = "2026-11-22"

    strings:
        $m1 = "metsrv.dll" ascii wide nocase
        $m2 = "metsrv.x64.dll" ascii wide nocase
        $m3 = "stdapi_sys_process_execute" ascii
        $m4 = "stdapi_fs_stat" ascii
        $m5 = "core_loadlib" ascii
        $m6 = "ReflectiveLoader" ascii

    condition:
        filesize < 15MB and
        (2 of ($m*))
}

rule C2_DNS_Tunneling_Script_Client : c2 tunneling
{
    meta:
        description = "Detects scripts implementing covert DNS TXT tunneling for Command & Control or data exfiltration"
        author = "BECETTI SECURITY"
        severity = "High"
        category = "C2-Implant"
        mitre = "T1071.004"
        reference = "https://attack.mitre.org/techniques/T1071/004/"
        date = "2026-11-22"

    strings:
        $d1 = "Resolve-DnsName" ascii wide nocase
        $d2 = "nslookup -q=txt" ascii wide nocase
        $d3 = "DnsQuery_A" ascii wide
        $t1 = "-Type TXT" ascii wide nocase
        $t2 = "FromBase64String" ascii wide nocase
        $t3 = "Invoke-Expression" ascii wide nocase
        $t4 = "IEX" ascii wide

    condition:
        filesize < 5MB and
        ($d1 or $d2 or $d3) and
        $t1 and
        ($t2 and ($t3 or $t4))
}
