# Prepares and verifies the Microsoft Store submission manifest.
#
# Why this exists: the CI package-msix job stamps a UNIQUE fourth version
# component (1.0.0.981) into Package.appxmanifest so every sideload build has
# a distinct package identity. Microsoft requires the fourth component to be
# 0 for a Store package ("reserved for Store use ... must be left as 0 when
# you build your package"), so the sideload .msix published on GitHub Releases
# can NOT be uploaded to Partner Center as-is.
#
# This script produces packaging\store\Package.store.appxmanifest (already
# committed - this script verifies it and can refresh it) and fails loudly on
# anything Microsoft would reject during certification:
#   - Version not 4 components / 4th component != 0 / Major == 0 / > 65535
#   - Identity Name or Publisher not identical to the sideload manifest
#     (identity must not drift silently; Partner Center is the source of truth
#     and a human confirms it - see docs/STORE-SUBMISSION.md)
#   - Any capability other than runFullTrust + internetClient
#   - Missing required tile/logo assets or wrong pixel dimensions
#
# Usage:
#   .\scripts\prepare-store-package.ps1            # verify + print summary
#   .\scripts\prepare-store-package.ps1 -Sync      # regenerate store manifest
#                                                  # from the sideload manifest
#                                                  # (keeps identity, forces .0)
param(
    [switch]$Sync,
    [string]$SideloadManifest = "src\Becetti.Security.App\Package.appxmanifest",
    [string]$StoreManifest    = "packaging\store\Package.store.appxmanifest"
)

$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
Set-Location $root

$errors   = New-Object System.Collections.Generic.List[string]
$warnings = New-Object System.Collections.Generic.List[string]

function Read-Manifest([string]$path) {
    if (-not (Test-Path $path)) { throw "Manifest not found: $path" }
    $xml = New-Object System.Xml.XmlDocument
    $xml.PreserveWhitespace = $true
    $xml.Load((Resolve-Path $path).Path)
    return $xml
}

# NOTE: the XmlNamespaceManager must be built from the XmlDocument's own
# NameTable inside plain .NET code. `New-Object XmlNamespaceManager($doc.NameTable)`
# wraps the NameTable and the manager ends up reading a PSObject instead of an
# XmlNameTable, so every XPath lookup below silently returns $null.
function New-ManifestNamespaceManager([System.Xml.XmlDocument]$doc) {
    $ns = [System.Xml.XmlNamespaceManager]::new($doc.NameTable)
    $ns.AddNamespace("f",      "http://schemas.microsoft.com/appx/manifest/foundation/windows10")
    $ns.AddNamespace("rescap", "http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities")
    $ns.AddNamespace("uap",    "http://schemas.microsoft.com/appx/manifest/uap/windows10")
    return $ns
}

Write-Host "=== BECETTI SECURITY - Store manifest preparation ===" -ForegroundColor Cyan
Write-Host "PowerShell $($PSVersionTable.PSVersion) on $([System.Environment]::OSVersion.VersionString)"
Write-Host "Manifests: sideload='$SideloadManifest' store='$StoreManifest' sync=$Sync"

if ($Sync) {
    $src = Read-Manifest $SideloadManifest
    $ns  = New-ManifestNamespaceManager $src

    $identity = $src.SelectSingleNode("/f:Package/f:Identity", $ns)
    if (-not $identity) { throw "No <Identity> in $SideloadManifest" }

    # Only the version is rewritten; Name/Publisher are copied verbatim so the
    # Store identity cannot silently diverge from the shipped package.
    $identity.SetAttribute("Version", "1.0.0.0")
    Write-Host "Rewrote Identity/@Version to 1.0.0.0 (Store requirement); Name and Publisher copied unchanged."
    $src.Save((Join-Path $root $StoreManifest))
}

try {
$store = Read-Manifest $StoreManifest
$side  = Read-Manifest $SideloadManifest

$nsStore = New-ManifestNamespaceManager $store
$nsSide  = New-ManifestNamespaceManager $side

$storeIdentity = $store.SelectSingleNode("/f:Package/f:Identity", $nsStore)
$sideIdentity  = $side.SelectSingleNode("/f:Package/f:Identity", $nsSide)

if (-not $storeIdentity) { throw "No <Identity> found in $StoreManifest - manifest is malformed." }
if (-not $sideIdentity)  { throw "No <Identity> found in $SideloadManifest - manifest is malformed." }

# ---- 1. Version rules (Microsoft: 4 parts, 4th must be 0, Major != 0, each <= 65535)
$version = $storeIdentity.GetAttribute("Version")
Write-Host "Store package version: $version"
$parts = $version -split '\.'
if ($parts.Count -ne 4) {
    $errors.Add("Version '$version' does not have exactly 4 components.")
} else {
    $numbers = @()
    foreach ($p in $parts) {
        $n = 0
        if (-not [int]::TryParse($p, [ref]$n)) { $errors.Add("Version component '$p' is not an integer."); continue }
        $numbers += $n
    }
    if ($numbers.Count -eq 4) {
        if ($numbers[3] -ne 0) { $errors.Add("Fourth version component is $($numbers[3]); Microsoft requires 0 for Store packages (it is reserved for Store use).") }
        if ($numbers[0] -eq 0)  { $errors.Add("First version component must not be 0.") }
        foreach ($n in $numbers) { if ($n -lt 0 -or $n -gt 65535) { $errors.Add("Version component $n is outside 0..65535.") } }
    }
}

# ---- 2. Identity must match the shipped package exactly (case-sensitive)
$nameStore  = $storeIdentity.GetAttribute("Name")
$pubStore   = $storeIdentity.GetAttribute("Publisher")
$archStore  = $storeIdentity.GetAttribute("ProcessorArchitecture")
$nameSide   = $sideIdentity.GetAttribute("Name")
$pubSide    = $sideIdentity.GetAttribute("Publisher")

Write-Host "Identity Name      : $nameStore"
Write-Host "Identity Publisher : $pubStore"
Write-Host "Architecture       : $archStore"

if ($nameStore -cne $nameSide) { $errors.Add("Store identity Name '$nameStore' differs from the shipped manifest '$nameSide'. Confirm BOTH against Partner Center before changing anything.") }
if ($pubStore  -cne $pubSide)  { $errors.Add("Store identity Publisher '$pubStore' differs from the shipped manifest '$pubSide'. Confirm BOTH against Partner Center before changing anything.") }
if ($archStore -ne "x64")      { $errors.Add("ProcessorArchitecture is '$archStore'; this submission only packages x64.") }

# Partner Center publishes the Publisher as CN=<GUID> for this account type.
if ($pubStore -notmatch '^CN=[0-9A-Fa-f-]{36}$') {
    $warnings.Add("Publisher '$pubStore' does not look like a CN=<GUID> Partner Center publisher ID. That is only correct if Partner Center really shows it that way - verify on Product identity.")
}

# ---- 3. Capabilities: only runFullTrust + internetClient may be requested
$declared = @()
foreach ($cap in $store.SelectNodes("/f:Package/f:Capabilities/*", $nsStore)) {
    $declared += $cap.GetAttribute("Name")
}
Write-Host ("Capabilities       : " + ($declared -join ", "))
$allowed = @("runFullTrust", "internetClient")
foreach ($d in $declared) {
    if ($allowed -notcontains $d) { $errors.Add("Undeclared-in-policy capability '$d' is present; this submission is reviewed for runFullTrust + internetClient only.") }
}
if ($declared -notcontains "runFullTrust") { $errors.Add("runFullTrust is missing - a packaged WinUI 3/.NET 8 app cannot start without it.") }
if ($declared -notcontains "internetClient") { $warnings.Add("internetClient is not declared; cloud features would fail at runtime.") }

# ---- 4. Target device family
$tdf = $store.SelectSingleNode("/f:Package/f:Dependencies/f:TargetDeviceFamily", $nsStore)
if (-not $tdf) { $errors.Add("No <TargetDeviceFamily> declared.") }
else {
    Write-Host "TargetDeviceFamily : $($tdf.GetAttribute('Name')) min $($tdf.GetAttribute('MinVersion')) / tested $($tdf.GetAttribute('MaxVersionTested'))"
    if ($tdf.GetAttribute("Name") -ne "Windows.Desktop") { $errors.Add("TargetDeviceFamily must be Windows.Desktop for this app.") }
}

# ---- 5. Assets: exist at the exact pixel sizes the manifest references
Add-Type -AssemblyName System.Drawing -ErrorAction SilentlyContinue
$assetChecks = @{
    "Assets\StoreLogo.png"        = @(50, 50)
    "Assets\Square44x44Logo.png"  = @(44, 44)
    "Assets\Square71x71Logo.png"  = @(71, 71)
    "Assets\Square150x150Logo.png"= @(150, 150)
    "Assets\Square310x310Logo.png"= @(310, 310)
    "Assets\Wide310x150Logo.png"  = @(310, 150)
}
$appDir = Split-Path $SideloadManifest -Parent
foreach ($rel in $assetChecks.Keys) {
    $full = Join-Path $appDir $rel
    if (-not (Test-Path $full)) { $errors.Add("Missing logo asset: $rel"); continue }
    $expected = $assetChecks[$rel]
    try {
        $img = [System.Drawing.Image]::FromFile((Resolve-Path $full).Path)
        $actual = @($img.Width, $img.Height)
        $img.Dispose()
        if ($actual[0] -ne $expected[0] -or $actual[1] -ne $expected[1]) {
            $errors.Add("$rel is $($actual[0])x$($actual[1]); the manifest/Store requires $($expected[0])x$($expected[1]).")
        } else {
            Write-Host "Asset OK           : $rel ($($actual[0])x$($actual[1]))"
        }
    } catch {
        $warnings.Add("Could not read image dimensions for $rel (System.Drawing unavailable): $($_.Exception.Message)")
    }
}

# ---- 6. Languages referenced by the package
$langs = @()
foreach ($r in $store.SelectNodes("/f:Package/f:Resources/f:Resource", $nsStore)) { $langs += $r.GetAttribute("Language") }
Write-Host ("Resource languages : " + ($langs -join ", "))

}
catch {
    Write-Host "::error::prepare-store-package.ps1 threw: $($_.Exception.GetType().Name): $($_.Exception.Message)"
    Write-Host "at: $($_.InvocationInfo.PositionMessage)"
    exit 2
}

Write-Host ""
if ($warnings.Count -gt 0) {
    Write-Host "WARNINGS ($($warnings.Count)):" -ForegroundColor Yellow
    foreach ($w in $warnings) { Write-Host "  - $w" -ForegroundColor Yellow }
}
if ($errors.Count -gt 0) {
    Write-Host "FAILED ($($errors.Count) problem(s)) - this manifest is NOT Store-submittable:" -ForegroundColor Red
    foreach ($e in $errors) {
        Write-Host "  - $e" -ForegroundColor Red
        Write-Host "::error::$e"
    }
    exit 1
}

Write-Host "Store manifest verification: PASS" -ForegroundColor Green
Write-Host "  $StoreManifest"
Write-Host "Next: scripts\package-store-upload.ps1 builds the unsigned .msixupload,"
Write-Host "      scripts\verify-store-package.ps1 checks the artifact and runs WACK."
