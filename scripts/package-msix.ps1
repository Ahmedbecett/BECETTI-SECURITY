# Packages the MSIX for Microsoft Store submission.
# Prerequisites (see docs/STORE-SUBMISSION.md):
#   - Windows SDK (MakeAppx.exe, SignTool.exe)
#   - A code-signing certificate whose Subject matches the Publisher in
#     src/Becetti.Security.App/Package.appxmanifest exactly:
#     CN=A5D5DC31-4A15-4059-8030-D96C51054596 (the verified Microsoft
#     Partner Center Windows Publisher ID for this account). Note that
#     matching this string does not by itself make a certificate trusted -
#     see docs/STORE-SUBMISSION.md for the Store-upload vs. direct-sideload
#     distinction.
$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
Set-Location $root

$publishDir = "src\Becetti.Security.App\bin\Release\net8.0-windows10.0.19041.0\win-x64\publish"
$packageDir = "packaging\output"
New-Item -ItemType Directory -Force -Path $packageDir | Out-Null

Write-Host "Publishing app..."
# Self-contained for BOTH .NET and the Windows App SDK: bundles .NET 8 and
# Windows App Runtime 1.8 directly in the output, so a sideloaded install
# does not depend on either being separately installed on the target
# machine. See docs/STORE-SUBMISSION.md for the "side-by-side configuration
# is incorrect" failure this fixes.
dotnet publish src\Becetti.Security.App\Becetti.Security.App.csproj -c Release -r win-x64 -p:Platform=x64 --self-contained true -p:WindowsAppSDKSelfContained=true

Write-Host "Packing MSIX..."
& makeappx pack /d $publishDir /p "$packageDir\BECETTI-SECURITY_1.0.1.0_x64.msix" /nv /o

Write-Host "Signing MSIX (requires a valid certificate)..."
# Replace with your certificate file and password. Never commit the .pfx.
# & signtool sign /fd SHA256 /a /f <certificate.pfx> /p <password> "$packageDir\BECETTI-SECURITY_1.0.1.0_x64.msix"

Write-Host "Done. Package is in $packageDir"
