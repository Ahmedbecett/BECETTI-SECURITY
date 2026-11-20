# Runs all tests. Core + API tests run on any OS; Windows-only behavior is
# exercised on a Windows machine (see docs/TESTING.md).
$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
Set-Location $root

dotnet test Becetti.Security.sln -c Release
