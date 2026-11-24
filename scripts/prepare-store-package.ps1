# Prepares and verifies the Microsoft Store submission manifest.
#
# Why this exists: the CI package-msix job stamps a UNIQUE fourth version
# component (1.0.0.981) into Package.appxmanifest so every sideload build has a
# distinct package identity. Microsoft requires the fourth component to be 0
# for a Store package ("reserved for Store use ... must be left as 0 when you
# build your package"), so the sideload .msix published on GitHub Releases can
# NOT be uploaded to Partner Center as-is.
#
# This script verifies packaging\store\Package.store.appxmanifest and fails on
# anything Microsoft would reject during certification:
#   - Version not 4 components / 4th component != 0 / Major == 0 / > 65535
#   - Identity Name or Publisher differing from the shipped sideload manifest
#     (identity must not drift silently; Partner Center is the source of truth)
#   - Any capability other than runFullTrust + internetClient
#   - Missing required tile/logo assets or wrong pixel dimensions
#
# Implementation note: the manifest is read with System.Xml.Linq (XDocument)
# and elements are matched on LocalName. XPath + XmlNamespaceManager proved
# unreliable here - a mis-bound XmlNamespaceManager makes SelectSingleNode
# throw MethodException for the 2-argument overload, and swallowing that would
# have hidden the identity checks entirely.
#
# Usage:
#   .\scripts\prepare-store-package.ps1            # verify
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

$script:errors   = New-Object 'System.Collections.Generic.List[string]'
$script:warnings = New-Object 'System.Collections.Generic.List[string]'

Add-Type -AssemblyName System.Xml.Linq -ErrorAction SilentlyContinue

function Read-ManifestDoc([string]$path) {
    if (-not (Test-Path $path)) { throw "Manifest not found: $path" }
    return [System.Xml.Linq.XDocument]::Load((Resolve-Path $path).Path)
}

# NOTE: return via a variable, never `return $parent.Elements()`. PowerShell
# unrolls a one-element collection into the element itself and wraps it in a
# PSObject, which then fails every .Name/.Elements() call with an unrelated
# "MethodException". Assign first, return the variable.
function Get-ChildByLocalName($parent, [string]$localName) {
    if ($null -eq $parent) { return $null }
    foreach ($child in $parent.Elements()) {
        if ($child.Name.LocalName -eq $localName) { return $child }
    }
    return $null
}

function Get-DescendantsByLocalName($parent, [string]$localName) {
    $result = New-Object 'System.Collections.Generic.List[object]'
    if ($null -eq $parent) { return $result }
    foreach ($el in $parent.Descendants()) {
        if ($el.Name.LocalName -eq $localName) { $result.Add($el) | Out-Null }
    }
    return $result
}

function Get-Attr($element, [string]$name) {
    if ($null -eq $element) { return $null }
    $attr = $element.Attribute($name)
    if ($null -eq $attr) { return $null }
    return [string]$attr.Value
}

function New-ManifestNamespaceManager([System.Xml.XmlDocument]$doc) {
    # Kept only for the -Sync path, which writes through XmlDocument so the
    # original file formatting is preserved. Verification never uses XPath.
    $nsm = [System.Xml.XmlNamespaceManager]::new($doc.NameTable)
    $nsm.AddNamespace("f", "http://schemas.microsoft.com/appx/manifest/foundation/windows10")
    $nsm.AddNamespace("rescap", "http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities")
    return $nsm
}

Write-Host "=== BECETTI SECURITY - Store manifest preparation ===" -ForegroundColor Cyan
Write-Host "PowerShell $($PSVersionTable.PSVersion) on Windows $([System.Environment]::OSVersion.Version)"
Write-Host "sideload=$SideloadManifest"
Write-Host "store=$StoreManifest  sync=$Sync"

try {
    if ($Sync) {
        $doc = New-Object System.Xml.XmlDocument
        $doc.PreserveWhitespace = $true
        $doc.Load((Resolve-Path $SideloadManifest).Path)
        $nsm = New-ManifestNamespaceManager $doc
        $identityNode = $doc.SelectSingleNode("/f:Package/f:Identity", $nsm)
        if ($null -eq $identityNode) { throw "No <Identity> element in $SideloadManifest" }
        # Only the version changes; Name and Publisher are copied verbatim.
        $identityNode.SetAttribute("Version", "1.0.1.0")
        $doc.Save((Join-Path $root $StoreManifest))
        Write-Host "Rewrote Identity/@Version to 1.0.1.0; Name and Publisher copied unchanged."
    }

    $storeDoc = Read-ManifestDoc $StoreManifest
    $sideDoc  = Read-ManifestDoc $SideloadManifest

    # The document root IS <Package> (appxmanifests have no outer wrapper).
    $storePkg = $storeDoc.Root
    $sidePkg  = $sideDoc.Root
    if ($null -eq $storePkg -or $storePkg.Name.LocalName -ne "Package") {
        throw "Store manifest root element is '$($storePkg.Name.LocalName)', expected <Package>."
    }
    if ($null -eq $sidePkg -or $sidePkg.Name.LocalName -ne "Package") {
        throw "Sideload manifest root element is '$($sidePkg.Name.LocalName)', expected <Package>."
    }

    $storeId = Get-ChildByLocalName $storePkg "Identity"
    $sideId  = Get-ChildByLocalName $sidePkg "Identity"
    if ($null -eq $storeId) { throw "No <Identity> in $StoreManifest" }
    if ($null -eq $sideId)  { throw "No <Identity> in $SideloadManifest" }
    # PublisherDisplayName is NOT part of package identity (it does not affect
    # Identity/@Name, Identity/@Publisher or signing), but Partner Center does
    # compare it against the account's "Publisher display name". It is checked
    # here so it cannot silently drift back to a value that fails ingestion.
    $expectedPublisherDisplayName = "Ahmedbecetti"
    foreach ($doc in @(@("store", $storePkg), @("sideload", $sidePkg))) {
        $label = $doc[0]; $pkgEl = $doc[1]
        $props = Get-ChildByLocalName $pkgEl "Properties"
        $pdn = $null
        if ($null -ne $props) { $pdn = Get-ChildByLocalName $props "PublisherDisplayName" }
        if ($null -eq $pdn) {
            $script:errors.Add("$label manifest has no <Properties>/<PublisherDisplayName>.")
        } else {
            $actual = [string]$pdn.Value
            if ($actual -ne $expectedPublisherDisplayName) {
                $script:errors.Add("$label PublisherDisplayName is '$actual', expected '$expectedPublisherDisplayName'. Partner Center compares this against the account's publisher display name.")
            }
        }
    }

    foreach ($pair in @(@("store", $storeId), @("sideload", $sideId))) {
        $label = $pair[0]; $el = $pair[1]
        if ($el -isnot [System.Xml.Linq.XElement]) {
            throw "Internal: $label <Identity> resolved to $($el.GetType().FullName), not XElement."
        }
    }

    $nameStore = Get-Attr $storeId "Name"
    $pubStore  = Get-Attr $storeId "Publisher"
    $verStore  = Get-Attr $storeId "Version"
    $archStore = Get-Attr $storeId "ProcessorArchitecture"

    Write-Host ""
    Write-Host "-- Identity (store manifest)"
    Write-Host "   Name        : $nameStore"
    Write-Host "   Publisher   : $pubStore"
    Write-Host "   Version     : $verStore"
    Write-Host "   Architecture: $archStore"

    # ---- 1. Version rules
    $parts = @($verStore -split '\.')
    if ($parts.Count -ne 4) {
        $script:errors.Add("Version '$verStore' does not have exactly 4 components.")
    } else {
        $numbers = New-Object 'System.Collections.Generic.List[int]'
        foreach ($p in $parts) {
            $n = 0
            if ([int]::TryParse($p, [ref]$n)) { $numbers.Add($n) | Out-Null }
            else { $script:errors.Add("Version component '$p' is not an integer.") }
        }
        if ($numbers.Count -eq 4) {
            if ($numbers[3] -ne 0) { $script:errors.Add("Fourth version component is $($numbers[3]); Microsoft requires 0 for Store packages (it is reserved for Store use).") }
            if ($numbers[0] -eq 0) { $script:errors.Add("First version component must not be 0.") }
            foreach ($n in $numbers) { if ($n -lt 0 -or $n -gt 65535) { $script:errors.Add("Version component $n is outside 0..65535.") } }
        }
    }

    # ---- 2. Identity must match the shipped package exactly (case-sensitive)
    $nameSide = Get-Attr $sideId "Name"
    $pubSide  = Get-Attr $sideId "Publisher"
    if ($nameStore -cne $nameSide) { $script:errors.Add("Store Name '$nameStore' differs from the shipped manifest '$nameSide'. Confirm BOTH in Partner Center before changing anything.") }
    if ($pubStore -cne $pubSide)   { $script:errors.Add("Store Publisher '$pubStore' differs from the shipped manifest '$pubSide'. Confirm BOTH in Partner Center before changing anything.") }
    if ($archStore -ne "x64")      { $script:errors.Add("ProcessorArchitecture is '$archStore'; this submission only packages x64.") }
    if ($pubStore -notmatch '^CN=[0-9A-Fa-f-]{36}$') {
        $script:warnings.Add("Publisher '$pubStore' does not look like a CN=<GUID> Partner Center publisher ID. Only correct if Partner Center really shows it that way.")
    }

    # ---- 3. Capabilities
    $capsParent = Get-ChildByLocalName $storePkg "Capabilities"
    $declared = New-Object 'System.Collections.Generic.List[string]'
    if ($null -ne $capsParent) {
        foreach ($cap in $capsParent.Elements()) { $declared.Add((Get-Attr $cap "Name")) | Out-Null }
    }
    Write-Host ("-- Capabilities: " + ($declared -join ", "))
    $allowed = @("runFullTrust", "internetClient")
    foreach ($d in $declared) {
        if ($allowed -notcontains $d) { $script:errors.Add("Capability '$d' is not part of this submission; only runFullTrust + internetClient are reviewed.") }
    }
    if ($declared -notcontains "runFullTrust") { $script:errors.Add("runFullTrust is missing - a packaged WinUI 3/.NET 8 app cannot start without it.") }
    if ($declared -notcontains "internetClient") { $script:warnings.Add("internetClient is not declared; cloud features would fail at runtime.") }

    # ---- 4. Target device family
    $deps = Get-ChildByLocalName $storePkg "Dependencies"
    $tdf = $null
    if ($null -ne $deps) { foreach ($c in $deps.Elements()) { if ($c.Name.LocalName -eq "TargetDeviceFamily") { $tdf = $c; break } } }
    if ($null -eq $tdf) {
        $script:errors.Add("No <TargetDeviceFamily> declared.")
    } else {
        $tdfName = Get-Attr $tdf "Name"
        Write-Host "-- TargetDeviceFamily: $tdfName min $(Get-Attr $tdf 'MinVersion') / tested $(Get-Attr $tdf 'MaxVersionTested')"
        if ($tdfName -ne "Windows.Desktop") { $script:errors.Add("TargetDeviceFamily must be Windows.Desktop for this app.") }
    }

    # ---- 5. Assets at the exact pixel sizes referenced
    $assetChecks = [ordered]@{
        "Assets\StoreLogo.png"         = @(50, 50)
        "Assets\Square44x44Logo.png"   = @(44, 44)
        "Assets\Square71x71Logo.png"   = @(71, 71)
        "Assets\Square150x150Logo.png" = @(150, 150)
        "Assets\Square310x310Logo.png" = @(310, 310)
        "Assets\Wide310x150Logo.png"   = @(310, 150)
    }
    $appDir = Split-Path $SideloadManifest -Parent
    $drawingOk = $true
    try { Add-Type -AssemblyName System.Drawing } catch { $drawingOk = $false }
    foreach ($rel in $assetChecks.Keys) {
        $full = Join-Path $appDir $rel
        if (-not (Test-Path $full)) { $script:errors.Add("Missing logo asset: $rel"); continue }
        $expected = $assetChecks[$rel]
        if (-not $drawingOk) { $script:warnings.Add("System.Drawing unavailable - could not verify dimensions of $rel."); continue }
        try {
            $img = [System.Drawing.Image]::FromFile((Resolve-Path $full).Path)
            $w = $img.Width; $h = $img.Height
            $img.Dispose()
            if ($w -ne $expected[0] -or $h -ne $expected[1]) {
                $script:errors.Add("$rel is ${w}x${h}; requires $($expected[0])x$($expected[1]).")
            } else {
                Write-Host "-- Asset OK: $rel (${w}x${h})"
            }
        } catch {
            $script:warnings.Add("Could not read $rel : $($_.Exception.Message)")
        }
    }

    # ---- 6. Resource languages
    $resParent = Get-ChildByLocalName $storePkg "Resources"
    $langs = New-Object 'System.Collections.Generic.List[string]'
    if ($null -ne $resParent) {
        foreach ($r in $resParent.Elements()) { if ($r.Name.LocalName -eq "Resource") { $langs.Add((Get-Attr $r "Language")) | Out-Null } }
    }
    Write-Host ("-- Resource languages: " + ($langs -join ", "))
}
catch {
    Write-Host "::error::prepare-store-package.ps1 threw: $($_.Exception.GetType().Name): $($_.Exception.Message)"
    Write-Host "at: $($_.InvocationInfo.PositionMessage)"
    exit 2
}

Write-Host ""
if ($script:warnings.Count -gt 0) {
    Write-Host "WARNINGS ($($script:warnings.Count)):" -ForegroundColor Yellow
    foreach ($w in $script:warnings) { Write-Host "  - $w" -ForegroundColor Yellow }
}
if ($script:errors.Count -gt 0) {
    Write-Host "FAILED ($($script:errors.Count) problem(s)) - this manifest is NOT Store-submittable:" -ForegroundColor Red
    foreach ($e in $script:errors) {
        Write-Host "  - $e" -ForegroundColor Red
        Write-Host "::error::$e"
    }
    exit 1
}

Write-Host "Store manifest verification: PASS" -ForegroundColor Green
Write-Host "  $StoreManifest"
Write-Host "Next: scripts\package-store-upload.ps1 builds the unsigned .msixupload"
Write-Host "      and scripts\verify-store-package.ps1 checks it and runs WACK."
