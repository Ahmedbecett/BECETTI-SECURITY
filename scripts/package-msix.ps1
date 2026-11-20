# Packages the MSIX for Microsoft Store submission.
# Prerequisites (see docs/STORE-SUBMISSION.md):
#   - Windows SDK (MakeAppx.exe, SignTool.exe)
#   - A code-signing certificate whose subject matches the Publisher in
#     src/Becetti.Security.App/Package.appxmanifest (CN=BECETTI placeholder).
$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
Set-Location $root

$publishDir = "src\Becetti.Security.App\bin\Release\net8.0-windows10.0.19041.0\win-x64\publish"
$packageDir = "packaging\output"
New-Item -ItemType Directory -Force -Path $packageDir | Out-Null

Write-Host "Publishing app..."
dotnet publish src\Becetti.Security.App\Becetti.Security.App.csproj -c Release -r win-x64 -p:Platform=x64 --self-contained false

Write-Host "Packing MSIX..."
& makeappx pack /d $publishDir /p "$packageDir\BECETTI-SECURITY_1.0.0.0_x64.msix" /nv /o

Write-Host "Signing MSIX (requires a valid certificate)..."
# Replace with your certificate file and password. Never commit the .pfx.
# & signtool sign /fd SHA256 /a /f <certificate.pfx> /p <password> "$packageDir\BECETTI-SECURITY_1.0.0.0_x64.msix"

Write-Host "Done. Package is in $packageDir"
