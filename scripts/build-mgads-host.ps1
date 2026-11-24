# Builds the MG Ads out-of-process host (net472) and generates the runtime
# config consumed by the WinUI 3 app.
#
# Why this is a separate step: the MG Ads C# SDK targets .NET Framework
# 4.7.2 / WinForms and cannot be loaded into the .NET 8 WinUI 3 process.
# The host is a small net472 WinForms process that runs the official SDK and
# paints its ad containers over the app window. The app's project includes
# MgAds\** and MgAdsHost\** as Content, so both must exist before the app
# project is evaluated (hence this script runs before msbuild on the app).
#
# Credentials are read from environment variables (never committed):
#   MGADS_APP_ID       - MG Ads application id (24-char hex)
#   MGADS_SECRET_KEY   - MG Ads application secret key
#
# Usage:
#   ./scripts/build-mgads-host.ps1
#   ./scripts/build-mgads-host.ps1 -AppId ... -SecretKey ...
#   ./scripts/build-mgads-host.ps1 -AllowMissingCredentials   # dev only
param(
    [string]$AppId = $env:MGADS_APP_ID,
    [string]$SecretKey = $env:MGADS_SECRET_KEY,
    [string]$BannerUnitId = "ce139ccaa1754b54909a1e9802f25721",
    [string]$FullScreenUnitId = "87675322692c4be2a66550cb86160f80",
    [string]$OutputDir = "src\Becetti.Security.App\MgAdsHost",
    [string]$ConfigDir = "src\Becetti.Security.App\MgAds",
    [switch]$AllowMissingCredentials
)

$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
Set-Location $root

$hostProject = "src\Becetti.Security.MgAdsHost\Becetti.Security.MgAdsHost.csproj"
if (-not (Test-Path $hostProject)) { throw "MG Ads host project not found: $hostProject" }

$configPath = Join-Path $ConfigDir "mgads.json"
$hasCredentials = -not ([string]::IsNullOrWhiteSpace($AppId) -or [string]::IsNullOrWhiteSpace($SecretKey))

if (-not $hasCredentials -and -not (Test-Path $configPath) -and -not $AllowMissingCredentials) {
    throw "MGADS_APP_ID and MGADS_SECRET_KEY must be set (or pass -AppId/-SecretKey), or commit MgAds\mgads.json."
}

if (-not $hasCredentials -and -not (Test-Path $configPath)) {
    Write-Host "MGADS_APP_ID / MGADS_SECRET_KEY are not set and no committed mgads.json was found - building the host without a runtime config (ads will be disabled)." -ForegroundColor Yellow
}

Write-Host "=== Building MG Ads host (net472, x64) ===" -ForegroundColor Cyan
if (Test-Path $OutputDir) { Remove-Item $OutputDir -Recurse -Force }
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

dotnet build $hostProject -c Release -f net472 -o $OutputDir --nologo
if ($LASTEXITCODE -ne 0) { throw "MG Ads host build failed with exit code $LASTEXITCODE" }

# The SDK's native WebView2 loader must keep its runtimes\win-x64\native
# relative path inside the host folder.
$loader = Join-Path $OutputDir "runtimes\win-x64\native\WebView2Loader.dll"
if (-not (Test-Path $loader)) {
    throw "WebView2Loader.dll was not copied to $loader - the MG Ads SDK payload is incomplete."
}

if ($hasCredentials) {
    Write-Host "=== Writing MgAds\mgads.json ===" -ForegroundColor Cyan
    New-Item -ItemType Directory -Force -Path $ConfigDir | Out-Null
    $config = [ordered]@{
        appId = $AppId
        secretKey = $SecretKey
        bannerUnitId = $BannerUnitId
        fullScreenUnitId = $FullScreenUnitId
    }
    $config | ConvertTo-Json | Set-Content -Path $configPath -Encoding utf8
    Write-Host "Wrote $configPath"
}
elseif (Test-Path $configPath) {
    Write-Host "Using committed $configPath (no MGADS_* environment override)." -ForegroundColor DarkCyan
}

if (Test-Path $configPath) {
    Write-Host "=== Probing the real MG Ads SDK on .NET Framework ===" -ForegroundColor Cyan
    & (Join-Path $OutputDir "Becetti.Security.MgAdsHost.exe") --probe --config $configPath
    if ($LASTEXITCODE -ne 0) { throw "MG Ads host --probe failed with exit code $LASTEXITCODE" }
}

Write-Host "MG Ads host ready: $OutputDir" -ForegroundColor Green
