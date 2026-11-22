/*
 * Webshell & Malicious Office Macro Indicators
 * Standard YARA 4.x rules.
 */

rule Suspicious_PHP_Webshell_Eval_Post : webshell php
{
    meta:
        description = "Detects PHP webshells executing arbitrary code directly from HTTP POST/REQUEST/COOKIE parameters via eval, assert, or system"
        author = "BECETTI SECURITY"
        severity = "High"
        category = "Webshell"
        reference = "https://attack.mitre.org/techniques/T1505/003/"
        date = "2026-11-22"

    strings:
        $php = "<?php" ascii nocase
        $p1 = "eval($_POST[" ascii nocase
        $p2 = "eval($_REQUEST[" ascii nocase
        $p3 = "eval(base64_decode($_POST[" ascii nocase
        $p4 = "system($_GET[" ascii nocase
        $p5 = "system($_POST[" ascii nocase
        $p6 = "passthru($_POST[" ascii nocase
        $p7 = "shell_exec($_REQUEST[" ascii nocase

    condition:
        filesize < 1MB and
        $php and
        1 of ($p1, $p2, $p3, $p4, $p5, $p6, $p7)
}

rule Suspicious_Office_Macro_AutoOpen_Shell : macro dropper
{
    meta:
        description = "Detects VBA macro source combining AutoOpen/Document_Open triggers with WScript.Shell or PowerShell command execution"
        author = "BECETTI SECURITY"
        severity = "High"
        category = "Macro-Dropper"
        reference = "https://attack.mitre.org/techniques/T1566/001/"
        date = "2026-11-22"

    strings:
        $auto1 = "Sub AutoOpen" ascii wide nocase
        $auto2 = "Sub Document_Open" ascii wide nocase
        $auto3 = "Sub Workbook_Open" ascii wide nocase
        $exec1 = "WScript.Shell" ascii wide nocase
        $exec2 = "CreateObject(\"Shell.Application\")" ascii wide nocase
        $exec3 = "powershell" ascii wide nocase
        $exec4 = "cmd.exe /c" ascii wide nocase

    condition:
        filesize < 5MB and
        1 of ($auto1, $auto2, $auto3) and
        1 of ($exec1, $exec2) and
        1 of ($exec3, $exec4)
}
