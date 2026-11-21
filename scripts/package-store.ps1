# Packages an UNSIGNED Microsoft Store upload package (.msixupload) for
# Partner Center submission. This is a DIFFERENT artifact from
# scripts/package-msix.ps1, which produces a self-signed .msix for direct
# sideload testing only (see docs/STORE-SUBMISSION.md).
#
# Why unsigned: Microsoft re-signs every package with its own trusted
# certificate during Store ingestion. Uploading a package signed with the
# development/test certificate is unnecessary and the Partner Center
# "StoreUpload" build mode produces an unsigned .msixupload by design -
# there is nothing to sign locally for this path.
#
# Prerequisites:
#   - Visual Studio Build Tools with the "Universal Windows Platform build
#     tools" and "Windows Application Packaging Project" components, OR a
#     full Visual Studio install with the UWP/WinUI workload.
#   - MSBuild on PATH (run from a "Developer PowerShell for VS" prompt).
#
# Usage:
#   .\scripts\package-store.ps1
#   .\scripts\package-store.ps1 -Version 1.1.0.0
#
# Output:
#   packaging\Becetti.Security.App.Package\AppPackages\
#     BECETTI SECURITY_<version>_Test\
#       BECETTI SECURITY_<version>_x64.msixupload
#
# Upload that .msixupload file directly in Partner Center -> your app's
# submission -> Packages -> drag and drop.

param(
    [string]$Version = "1.0.0.0"
)

$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
Set-Location $root

$wapproj = "packaging\Becetti.Security.App.Package\Becetti.Security.App.Package.wapproj"

if (-not (Test-Path $wapproj)) {
    throw "Packaging project not found at $wapproj"
}

Write-Host "Restoring NuGet packages..."
& msbuild $wapproj /t:Restore /p:Configuration=Release /p:Platform=x64

Write-Host "Building Store upload package (unsigned .msixupload, version $Version)..."
& msbuild $wapproj `
    /t:Build `
    /p:Configuration=Release `
    /p:Platform=x64 `
    /p:AppxBundle=Never `
    /p:AppxPackageSigningEnabled=false `
    /p:UapAppxPackageBuildMode=StoreUpload `
    /p:AppxPackageVersion=$Version `
    /p:GenerateAppInstallerFile=false

if ($LASTEXITCODE -ne 0) {
    throw "MSBuild failed with exit code $LASTEXITCODE"
}

$output = Get-ChildItem -Path "packaging\Becetti.Security.App.Package\AppPackages" -Filter "*.msixupload" -Recurse |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1

if ($null -eq $output) {
    throw "Build succeeded but no .msixupload was found under packaging\Becetti.Security.App.Package\AppPackages"
}

Write-Host ""
Write-Host "Store upload package ready: $($output.FullName)"
Write-Host "Upload this file directly in Partner Center. Do not sign it manually -"
Write-Host "Microsoft signs it with its own certificate during certification."
