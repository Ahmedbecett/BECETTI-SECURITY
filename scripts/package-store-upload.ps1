# Builds the UNSIGNED Microsoft Store submission package (.msixupload).
#
# Store requirement this encodes (learn.microsoft.com/windows/apps/publish/
# publish-your-app/msix/app-package-requirements): "Your MSIX and AppX
# packages don't have to be signed with a certificate rooted in a trusted
# certificate authority when submitting to the Microsoft Store. The Microsoft
# Store will automatically re-sign your MSIX/AppX packages with a Microsoft
# certificate during the publishing process after your app passes
# certification." The CI test certificate (BecettiTestCert.pfx/.cer) is used
# ONLY by the sideload job; this script never touches it, and the build runs
# with AppxPackageSigningEnabled=false.
#
# Two artifacts come out of StoreUpload mode:
#   *.msix            - the package inside the upload (unsigned)
#   *.msixupload      - the file you drag into Partner Center -> Packages
# A .msixupload also carries the .appxsym (public symbols) used by Partner
# Center crash analytics; deleting it is allowed but loses that reporting.
#
# Usage:
#   .\scripts\package-store-upload.ps1
#   .\scripts\package-store-upload.ps1 -Version 1.1.0.0
#   .\scripts\package-store-upload.ps1 -SkipWack
#
# Output:
#   artifacts\store\BECETTI-SECURITY_<version>_x64.msixupload
param(
    [string]$Version = "1.0.0.0",
    [switch]$SkipWack
)

$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
Set-Location $root

# Full transcript on disk. The Actions log blobs are not retrievable from the
# build agent, so when this script fails the only readable evidence is a file
# the workflow can turn into annotations (see the summary step) or upload.
$logDir = Join-Path $root "artifacts\store"
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
$transcript = Join-Path $logDir "package-store-upload.log"
Start-Transcript -Path $transcript -Force | Out-Null

# Any throw in this script used to exit pwsh with a bare code 1 and no
# annotation, so every failure looked identical ("Process completed with exit
# code 1."). Report the type and message, then rethrow.
trap {
    $msg = "$($_.Exception.GetType().Name): $($_.Exception.Message)"
    Write-Host "::error::package-store-upload.ps1 threw: $msg"
    Write-Host "::error::$($_.InvocationInfo.PositionMessage)"
    Stop-Transcript | Out-Null
    exit 1
}

# The Store reserves the 4th version field; refuse to produce a package that
# Partner Center would bounce at validation time.
if ($Version -notmatch '^\d+\.\d+\.\d+\.0$') {
    throw "Store package version must be <major>.<minor>.<build>.0 (fourth component reserved by the Store). Got: $Version"
}
if ($Version -match '^0\.') {
    throw "The first version component cannot be 0 for a Store package. Got: $Version"
}

Write-Host "=== 1/5 Preparing and verifying the Store manifest ===" -ForegroundColor Cyan
& (Join-Path $PSScriptRoot "prepare-store-package.ps1")

$storeManifest = Join-Path $root "packaging\store\Package.store.appxmanifest"
$appManifest   = Join-Path $root "src\Becetti.Security.App\Package.appxmanifest"

# Build from the Store manifest without rewriting the committed sideload
# manifest: swap it in for the duration of the build, restore it afterwards
# (even on failure) so the repo file is never left in a Store-only state.
$sideloadBackup = Get-Content $appManifest -Raw
try {
    Copy-Item $storeManifest $appManifest -Force
    Write-Host "Using packaging\store\Package.store.appxmanifest for this build (Version=$Version)."

    Write-Host ""
    Write-Host "=== 2/5 Building official YARA engine (native x64, required by the app) ===" -ForegroundColor Cyan
    & (Join-Path $PSScriptRoot "build-yara-win64.ps1")

    Write-Host ""
    Write-Host "=== 3/5 Restoring (msbuild; single-project MSIX needs the packaging targets) ===" -ForegroundColor Cyan
    & msbuild "src\Becetti.Security.App\Becetti.Security.App.csproj" /t:Restore `
        /p:Configuration=Release /p:Platform=x64 /p:RuntimeIdentifier=win-x64 `
        /p:SelfContained=true /p:WindowsAppSDKSelfContained=true
    if ($LASTEXITCODE -ne 0) { throw "Restore failed with exit code $LASTEXITCODE" }

    $outDir = Join-Path $root "artifacts\store\packages\"
    New-Item -ItemType Directory -Force -Path $outDir | Out-Null

    Write-Host ""
    Write-Host "=== 4/5 Packing the unsigned StoreUpload bundle ===" -ForegroundColor Cyan
    # AppxPackageSigningEnabled=false is the Microsoft-documented CI recipe
    # (learn.microsoft.com/windows/apps/package-and-deploy/ci-for-winui3):
    # the Store re-signs the package, so no local certificate is involved.
    & msbuild "src\Becetti.Security.App\Becetti.Security.App.csproj" `
        /p:Configuration=Release `
        /p:Platform=x64 `
        /p:RuntimeIdentifier=win-x64 `
        /p:SelfContained=true `
        /p:WindowsAppSDKSelfContained=true `
        /p:UapAppxPackageBuildMode=StoreUpload `
        /p:AppxBundle=Never `
        /p:AppxPackageSigningEnabled=false `
        /p:AppxPackageVersion=$Version `
        /p:AppxPackageDir=$outDir `
        /p:GenerateAppxPackageOnBuild=true `
        /p:GenerateAppInstallerFile=false
    if ($LASTEXITCODE -ne 0) { throw "Store package build failed with exit code $LASTEXITCODE" }
}
finally {
    # Restore the committed sideload manifest verbatim.
    Set-Content -Path $appManifest -Value $sideloadBackup -NoNewline
    Write-Host "Restored src\Becetti.Security.App\Package.appxmanifest (sideload identity untouched)."
}

$upload = Get-ChildItem -Path $outDir -Filter "*.msixupload" -Recurse |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $upload) {
    throw "Build succeeded but no .msixupload was produced under $outDir"
}

$msix = Get-ChildItem -Path $outDir -Filter "*.msix" -Recurse |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1

$finalDir = Join-Path $root "artifacts\store"
New-Item -ItemType Directory -Force -Path $finalDir | Out-Null
$finalName = "BECETTI-SECURITY_$($Version)_x64.msixupload"
Copy-Item $upload.FullName (Join-Path $finalDir $finalName) -Force

Write-Host ""
Write-Host "=== 5/5 Verifying the artifact ===" -ForegroundColor Cyan
$verifyArgs = @{ PackagePath = (Join-Path $finalDir $finalName) }
if ($SkipWack) { $verifyArgs["SkipWack"] = $true }
& (Join-Path $PSScriptRoot "verify-store-package.ps1") @verifyArgs

Write-Host ""
Write-Host "Store upload package ready: artifacts\store\$finalName" -ForegroundColor Green
if ($msix) {
    Write-Host "Inner package: $($msix.Name) ($([math]::Round($msix.Length / 1MB, 1)) MB)"
    $sha = (Get-FileHash $msix.FullName -Algorithm SHA256).Hash
    Write-Host "Inner .msix SHA-256: $sha"
}
Write-Host "Upload the .msixupload in Partner Center -> your app -> Packages."
Write-Host "Do NOT sign it locally: the Store replaces the signature with Microsoft's own."
Stop-Transcript | Out-Null
