# Regenerates packaging/winget/Becetti.Security.yaml from a real, published
# sideload MSIX, so the manifest can never ship a placeholder hash or a URL that
# does not resolve.
#
# Why this exists: the committed manifest pointed at
# `releases/latest/download/BECETTI-SECURITY_x64.msix`. The sideload asset is
# named `BECETTI-SECURITY_<version>_x64.msix`, so that path 404s on every
# release, and `InstallerSha256` was a placeholder string. Both are rejected by
# winget-pkgs validation.
#
# Usage (run on Windows against an already-published asset):
#   .\scripts\update-winget-manifest.ps1 -Tag msix-test-4d18851 `
#       -AssetName BECETTI-SECURITY_1.0.0.1171_x64.msix `
#       -PackagePath .\BECETTI-SECURITY_1.0.0.1171_x64.msix
param(
    [Parameter(Mandatory = $true)][string]$Tag,
    [Parameter(Mandatory = $true)][string]$AssetName,
    [Parameter(Mandatory = $true)][string]$PackagePath
)

$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
$manifest = Join-Path $root "packaging\winget\Becetti.Security.yaml"

if (-not (Test-Path $PackagePath)) { throw "Package not found: $PackagePath" }
if ($AssetName -notmatch 'BECETTI-SECURITY_(\d+\.\d+\.\d+\.\d+)_x64\.msix$') {
    throw "Asset name does not carry a version: $AssetName"
}
$version = $Matches[1]
$sha = (Get-FileHash $PackagePath -Algorithm SHA256).Hash
$url = "https://github.com/Ahmedbecett/BECETTI-SECURITY/releases/download/$Tag/$AssetName"

$text = Get-Content $manifest -Raw
$text = $text -replace '(?m)^PackageVersion: .*$', "PackageVersion: $version"
$text = $text -replace '(?m)^    InstallerUrl: .*$', "    InstallerUrl: $url"
$text = $text -replace '(?m)^    InstallerSha256: .*$', "    InstallerSha256: $sha"
Set-Content -Path $manifest -Value $text -NoNewline

Write-Host "winget manifest updated:"
Write-Host "  version: $version"
Write-Host "  url    : $url"
Write-Host "  sha256 : $sha"
