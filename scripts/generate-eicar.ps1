# Generates the EICAR antivirus test file LOCALLY for controlled testing only.
# The file is NOT committed to the repository. Use it only on test machines
# to verify that Defender detects the standard test string, per
# https://www.eicar.org/ — never on production systems.
$ErrorActionPreference = "Stop"

$eicar = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
$path = Join-Path $PSScriptRoot "eicar.com"

[System.IO.File]::WriteAllText($path, $eicar)
Write-Host "EICAR test file written to $path (68 bytes)."
Write-Host "Scan it with Defender to verify detection. Delete it afterwards."
