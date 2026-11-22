/*
 * Suspicious Windows PE & Credential-Theft Indicators
 * Uses standard YARA 4.x byte/string matching (compatible with all standard YARA builds).
 */

rule Suspicious_PE_Process_Injection_APIs : pe injection
{
    meta:
        description = "Detects Windows PE files referencing a classic remote process-injection API chain together with suspicious dynamic resolution indicators"
        author = "BECETTI SECURITY"
        severity = "Medium"
        category = "Trojan"
        reference = "https://attack.mitre.org/techniques/T1055/"
        date = "2026-11-22"

    strings:
        $api1 = "VirtualAllocEx" ascii wide
        $api2 = "WriteProcessMemory" ascii wide
        $api3 = "CreateRemoteThread" ascii wide
        $api4 = "NtUnmapViewOfSection" ascii wide
        $api5 = "SetThreadContext" ascii wide
        $api6 = "ResumeThread" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 20MB and
        ($api1 and $api2 and ($api3 or ($api4 and $api5 and $api6)))
}

rule Suspicious_Credential_Dump_Indicators : credential_access
{
    meta:
        description = "Detects binaries or scripts referencing LSASS memory dumping together with SeDebugPrivilege escalation strings"
        author = "BECETTI SECURITY"
        severity = "Critical"
        category = "Credential-Theft"
        reference = "https://attack.mitre.org/techniques/T1003/001/"
        date = "2026-11-22"

    strings:
        $s1 = "lsass.exe" ascii wide nocase
        $s2 = "MiniDumpWriteDump" ascii wide
        $s3 = "SeDebugPrivilege" ascii wide
        $s4 = "sekurlsa::logonpasswords" ascii wide nocase
        $s5 = "comsvcs.dll" ascii wide nocase
        $s6 = "MiniDump" ascii wide nocase

    condition:
        filesize < 25MB and
        (
            $s4 or
            ($s1 and $s2 and $s3) or
            ($s1 and $s5 and $s6)
        )
}

rule Suspicious_Reverse_Shell_Script : backdoor shell
{
    meta:
        description = "Detects scripts implementing a raw TCP reverse shell piped directly into cmd.exe or /bin/sh"
        author = "BECETTI SECURITY"
        severity = "High"
        category = "Backdoor"
        reference = "https://attack.mitre.org/techniques/T1059/"
        date = "2026-11-22"

    strings:
        $tcp = "System.Net.Sockets.TCPClient" ascii wide nocase
        $stream = "GetStream()" ascii wide nocase
        $iex = "iex " ascii wide nocase
        $bash_rev = "/dev/tcp/" ascii
        $bash_redir = "0>&1" ascii
        $py_sock = "socket.socket(" ascii
        $py_dup = "os.dup2(" ascii
        $py_pty = "subprocess.call([\"/bin/sh\"" ascii

    condition:
        filesize < 2MB and
        (
            ($tcp and $stream and $iex) or
            ($bash_rev and $bash_redir) or
            ($py_sock and $py_dup and $py_pty)
        )
}
