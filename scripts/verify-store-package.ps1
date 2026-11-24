# Verifies a Microsoft Store submission artifact (.msixupload or .msix):
#   - package integrity (opens as a ZIP, AppxManifest.xml parses)
#   - identity/version/capabilities read from the PACKAGE, not from the repo
#     (catches a stale or hand-edited manifest slipping through)
#   - architecture: exactly x64, no foreign-architecture binaries
#   - unsigned, as required for Store upload (an AppxSignature.p7x means a
#     local/test certificate was applied - Partner Center wants the Store to
#     re-sign it, and a test-cert signature can trip publisher validation)
#   - required runtime payload present (app exe, native YARA engine, rules,
#     third-party license notices, resources.pri)
#   - SHA-256 of the artifact for the submission record
#   - Windows App Certification Kit (WACK / appcert.exe) run when available
#
# Usage:
#   .\scripts\verify-store-package.ps1 -PackagePath artifacts\store\X.msixupload
#   .\scripts\verify-store-package.ps1 -PackagePath X.msix -SkipWack
param(
    [Parameter(Mandatory = $true)][string]$PackagePath,
    [switch]$SkipWack
)

$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
Set-Location $root

if (-not (Test-Path $PackagePath)) { throw "Artifact not found: $PackagePath" }
$pkgPath = (Resolve-Path $PackagePath).Path
$reportDir = Join-Path $root "artifacts\store"
New-Item -ItemType Directory -Force -Path $reportDir | Out-Null
$reportPath = Join-Path $reportDir "store-package-verification.txt"

$lines = New-Object System.Collections.Generic.List[string]
$script:errors = New-Object System.Collections.Generic.List[string]
function Log([string]$msg) { Write-Host $msg; $lines.Add($msg) | Out-Null }

Add-Type -AssemblyName System.IO.Compression.FileSystem

Log "=== BECETTI SECURITY - Store artifact verification ==="
Log "Artifact : $pkgPath"
Log "Size     : $([math]::Round((Get-Item $pkgPath).Length / 1MB, 2)) MB"
$sha256 = (Get-FileHash $pkgPath -Algorithm SHA256).Hash
Log "SHA-256  : $sha256"
Log ""

# ---- Locate the inner .msix (an .msixupload is a ZIP containing it)
$isUpload = $pkgPath.ToLower().EndsWith(".msixupload")
$work = Join-Path ([System.IO.Path]::GetTempPath()) ("becetti-store-verify-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $work | Out-Null

try {
    if ($isUpload) {
        Log "-- .msixupload contains:"
        $uploadZip = [System.IO.Compression.ZipFile]::OpenRead($pkgPath)
        try {
            foreach ($e in $uploadZip.Entries) { Log "   $($e.FullName) ($($e.Length) bytes)" }
            $inner = $uploadZip.Entries | Where-Object { $_.FullName.ToLower().EndsWith(".msix") } | Select-Object -First 1
            if (-not $inner) { throw "No inner .msix inside the .msixupload - not a valid Store upload." }
            $innerPath = Join-Path $work "inner.msix"
            [System.IO.Compression.ZipFileExtensions]::ExtractToFile($inner, $innerPath, $true)
        } finally { $uploadZip.Dispose() }
    } else {
        $innerPath = $pkgPath
    }
    Log ""

    $zip = [System.IO.Compression.ZipFile]::OpenRead($innerPath)
    try {
        $entries = $zip.Entries

        # ---- 1. Structure
        $manifestEntry = $entries | Where-Object { $_.FullName -eq "AppxManifest.xml" } | Select-Object -First 1
        if (-not $manifestEntry) { $script:errors.Add("AppxManifest.xml missing - not a valid package.") }
        else {
            $reader = New-Object System.IO.StreamReader($manifestEntry.Open())
            $manifestXml = $reader.ReadToEnd(); $reader.Dispose()
            # Parsed with XDocument and matched on LocalName: XPath through an
            # XmlNamespaceManager proved unreliable in this script's hosting
            # environment, and a failure there would skip the identity checks.
            $doc = [System.Xml.Linq.XDocument]::Parse($manifestXml)
            # AppxManifest.xml's root element is <Package>; do not go looking for
            # it as a child (a one-element pipeline result would come back wrapped).
            $pkgEl = $doc.Root
            if ($null -eq $pkgEl -or $pkgEl.Name.LocalName -ne "Package") {
                throw "AppxManifest.xml root is '$($pkgEl.Name.LocalName)', expected <Package>."
            }

            function Get-LocalChild($parent, [string]$localName) {
                foreach ($c in $parent.Elements()) { if ($c.Name.LocalName -eq $localName) { return $c } }
                return $null
            }
            function Get-LocalAttr($el, [string]$attrName) {
                if ($null -eq $el) { return $null }
                $a = $el.Attribute($attrName)
                if ($null -eq $a) { return $null }
                return [string]$a.Value
            }

            $id = Get-LocalChild $pkgEl "Identity"
            if ($null -eq $id) { throw "AppxManifest.xml has no <Identity> element." }
            $name = Get-LocalAttr $id "Name"; $pub = Get-LocalAttr $id "Publisher"
            $ver  = Get-LocalAttr $id "Version"; $arch = Get-LocalAttr $id "ProcessorArchitecture"
            Log "-- Identity inside the package:"
            Log "   Name        : $name"
            Log "   Publisher   : $pub"
            Log "   Version     : $ver"
            Log "   Architecture: $arch"

            if ($ver -notmatch '^\d+\.\d+\.\d+\.0$') { $script:errors.Add("Packaged version '$ver' does not end in .0 - the Store reserves the fourth component.") }
            if ($arch -ne "x64") { $script:errors.Add("Packaged architecture is '$arch', expected x64.") }

            $caps = @()
            $capsParent = Get-LocalChild $pkgEl "Capabilities"
            if ($null -ne $capsParent) {
                foreach ($c in $capsParent.Elements()) { $caps += (Get-LocalAttr $c "Name") }
            }
            Log ("   Capabilities: " + ($caps -join ", "))
            foreach ($c in $caps) { if (@("runFullTrust", "internetClient") -notcontains $c) { $script:errors.Add("Unexpected capability '$c' in the package.") } }
            if ($caps -notcontains "runFullTrust") { $script:errors.Add("runFullTrust missing from the package.") }
        }

        # ---- 2. Must be unsigned for Store upload
        $sig = $entries | Where-Object { $_.FullName -eq "AppxSignature.p7x" } | Select-Object -First 1
        if ($sig) {
            $script:errors.Add("Package IS signed (AppxSignature.p7x present). The Store submission artifact must be unsigned - the Store re-signs it after certification. Build with AppxPackageSigningEnabled=false.")
        } else {
            Log "-- Signature: none (correct for Store upload; Microsoft re-signs after certification)."
        }

        # ---- 3. Required payload
        $normalized = $entries | ForEach-Object { ($_.FullName -replace '\\', '/') }
        $required = @(
            "Becetti.Security.App.exe",
            "resources.pri",
            "Native/yara/win-x64/yara64.exe",
            "Native/yara/win-x64/yarac64.exe",
            "Rules/yara/eicar_standard_test.yar",
            "THIRD-PARTY-LICENSES/YARA-LICENSE.txt",
            "MgAds/mgads.json",
            "MgAdsHost/Becetti.Security.MgAdsHost.exe",
            "MgAdsHost/MiracleGamesAd.dll",
            "MgAdsHost/runtimes/win-x64/native/WebView2Loader.dll"
        )
        foreach ($req in $required) {
            if ($normalized -contains $req) { Log "-- Present: $req" }
            else { $script:errors.Add("Required file missing from the package: $req") }
        }

        # Evidence, not guesswork: when a required path is missing the report
        # must show where the files actually landed, otherwise every fix is a
        # blind retry.
        if ($script:errors.Count -gt 0) {
            Log ""
            Log "-- Package layout (files matching the expected names, for diagnosis):"
            $interesting = $normalized | Where-Object {
                $_ -match '(?i)(\.exe$|\.yar$|\.pri$|license)'
            } | Sort-Object
            foreach ($f in ($interesting | Select-Object -First 60)) { Log "   $f" }
            if ($interesting.Count -gt 60) { Log "   ... $($interesting.Count - 60) more" }
        }

        # ---- 4. Architecture sanity: no non-x64 native payload in the way
        $badArch = $normalized | Where-Object {
            $_ -match '(^|/)(x86|arm64|arm)(/|$)' -or $_ -match '(?i)(win-x86|win-arm64)'
        }
        if ($badArch) {
            # Dependencies folders for other architectures are a real risk
            # (makes the Store offer a package the device cannot run).
            $script:errors.Add("Package contains binaries for another architecture: " + (($badArch | Select-Object -First 5) -join ", "))
        } else {
            Log "-- Architecture: no x86/ARM payload present."
        }

        Log ""
        Log "Total files in package: $($entries.Count)"
    } finally { $zip.Dispose() }

    # ---- 5. WACK (Windows App Certification Kit)
    if ($SkipWack) {
        Log "-- WACK: skipped (-SkipWack)."
    } else {
        $appcert = $null
        $kitRoot = "${env:ProgramFiles(x86)}\Windows Kits\10\App Certification Kit"
        $direct  = Join-Path $kitRoot "appcert.exe"
        if (Test-Path $direct) { $appcert = Get-Item $direct }
        if (-not $appcert) {
            # Windows App Cert Kit also ships in version-stamped SDK bin folders on
            # some runner images - search for it rather than assuming one layout.
            $appcert = Get-ChildItem -Path "${env:ProgramFiles(x86)}\Windows Kits" -Filter "appcert.exe" -Recurse -ErrorAction SilentlyContinue |
                Select-Object -First 1
        }

        if (-not $appcert) {
            Log ""
            Log "WACK: appcert.exe not found on this machine (install the Windows SDK's"
            Log "      'Windows App Certification Kit' component). This run does NOT"
            Log "      constitute a WACK pass - run store-package.yml on a runner image"
            Log "      that ships the kit, or run WACK manually on Windows."
        } else {
            Log ""
            Log "WACK binary: $($appcert.FullName)"
            # Name the report in its final form: NTFS is case-insensitive, so
            # producing wack-report.xml and then copying it to WACK-REPORT.xml
            # is a self-copy that throws "Cannot overwrite the item ... with
            # itself".
            $wackReport = Join-Path $reportDir "WACK-REPORT.xml"
            if (Test-Path $wackReport) { Remove-Item $wackReport -Force }
            Log ""
            Log "-- Running WACK against the inner .msix:"
            & $appcert.FullName reset | Out-Null
            & $appcert.FullName test -appxpackagepath $innerPath -reportoutputpath $wackReport 2>&1 | ForEach-Object { Log "   $_" }
            $wackExit = $LASTEXITCODE
            Log "   appcert.exe exit code: $wackExit  (0=pass, 1=needs finalization, negative=failure)"

            if ($wackExit -eq 1) {
                & $appcert.FullName finalizereport -reportfilepath $wackReport 2>&1 | ForEach-Object { Log "   $_" }
            }
            if (Test-Path $wackReport) {
                $w = [System.Xml.Linq.XDocument]::Load((Resolve-Path $wackReport).Path)
                $requirements = @()
                foreach ($el in $w.Descendants()) {
                    if ($el.Name.LocalName -eq "REQUIREMENT") { $requirements += $el }
                }
                $overall = $requirements | Where-Object {
                    $a = $_.Attribute("NAME"); $a -and ([string]$a.Value) -match 'OVERALL'
                } | Select-Object -First 1
                if ($overall) {
                    $st = $overall.Attribute("STATUS")
                    Log "   OVERALL_RESULT: $([string]$st.Value)"
                }
                $nonPass = 0
                foreach ($req in $requirements) {
                    $stAttr = $req.Attribute("STATUS")
                    $status = if ($stAttr) { [string]$stAttr.Value } else { $null }
                    if ($status -and $status -ne "PASS") {
                        $n = $req.Attribute("NAME"); $d = $req.Attribute("DESCRIPTION"); $m = $req.Attribute("MESSAGE")
                        Log "   [$status] $([string]$n.Value) - $([string]$d.Value) $([string]$m.Value)"
                        $nonPass++
                    }
                }
                if ($nonPass -eq 0) { Log "   All WACK requirements in the report are PASS." }
            } else {
                Log "   WACK produced no report file."
            }
        }
    }
}
catch {
    Write-Host "::error::Store verification threw: $($_.Exception.GetType().Name): $($_.Exception.Message)"
    Log ""
    Log "RESULT: FAILED (verification threw)"
    Log "  $($_.Exception.GetType().FullName): $($_.Exception.Message)"
    Log $_.ScriptStackTrace
    $lines | Set-Content $reportPath -Encoding utf8
    throw
}
finally {
    if (Test-Path $work) { Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue }
}

Log ""
Log "SHA-256 (artifact): $sha256"
if ($errors.Count -gt 0) {
    Log ""
    Log "RESULT: FAILED ($($errors.Count) problem(s))"
    foreach ($e in $errors) {
        Log "  - $e"
        # Annotations are the only channel that survives in this environment
        # (Actions log blobs are not readable from the agent), so every failed
        # check has to be raised here as well as written to the report.
        Write-Host "::error::$e"
    }
    $lines | Set-Content $reportPath -Encoding utf8
    Write-Host "Report: $reportPath" -ForegroundColor Red
    exit 1
}

Log "RESULT: PASS (structure, identity, capabilities, architecture, payload)"
$lines | Set-Content $reportPath -Encoding utf8
Write-Host "Report: $reportPath" -ForegroundColor Green
