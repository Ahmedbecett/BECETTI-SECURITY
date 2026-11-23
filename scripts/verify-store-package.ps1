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
$errors = New-Object System.Collections.Generic.List[string]
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
        if (-not $manifestEntry) { $errors.Add("AppxManifest.xml missing - not a valid package.") }
        else {
            $reader = New-Object System.IO.StreamReader($manifestEntry.Open())
            $manifestXml = $reader.ReadToEnd(); $reader.Dispose()
            $doc = New-Object System.Xml.XmlDocument
            $doc.LoadXml($manifestXml)
            # Plain .NET construction: New-Object XmlNamespaceManager($doc.NameTable)
            # wraps the NameTable in a PSObject and every XPath lookup then returns
            # $null, which would silently skip the identity/capability checks.
            $ns = [System.Xml.XmlNamespaceManager]::new($doc.NameTable)
            $ns.AddNamespace("f", "http://schemas.microsoft.com/appx/manifest/foundation/windows10")

            $id = $doc.SelectSingleNode("/f:Package/f:Identity", $ns)
            $name = $id.GetAttribute("Name"); $pub = $id.GetAttribute("Publisher")
            $ver  = $id.GetAttribute("Version"); $arch = $id.GetAttribute("ProcessorArchitecture")
            Log "-- Identity inside the package:"
            Log "   Name        : $name"
            Log "   Publisher   : $pub"
            Log "   Version     : $ver"
            Log "   Architecture: $arch"

            if ($ver -notmatch '^\d+\.\d+\.\d+\.0$') { $errors.Add("Packaged version '$ver' does not end in .0 - the Store reserves the fourth component.") }
            if ($arch -ne "x64") { $errors.Add("Packaged architecture is '$arch', expected x64.") }

            $caps = @()
            foreach ($c in $doc.SelectNodes("/f:Package/f:Capabilities/*", $ns)) { $caps += $c.GetAttribute("Name") }
            Log ("   Capabilities: " + ($caps -join ", "))
            foreach ($c in $caps) { if (@("runFullTrust", "internetClient") -notcontains $c) { $errors.Add("Unexpected capability '$c' in the package.") } }
            if ($caps -notcontains "runFullTrust") { $errors.Add("runFullTrust missing from the package.") }
        }

        # ---- 2. Must be unsigned for Store upload
        $sig = $entries | Where-Object { $_.FullName -eq "AppxSignature.p7x" } | Select-Object -First 1
        if ($sig) {
            $errors.Add("Package IS signed (AppxSignature.p7x present). The Store submission artifact must be unsigned - the Store re-signs it after certification. Build with AppxPackageSigningEnabled=false.")
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
            "THIRD-PARTY-LICENSES/YARA-LICENSE.txt"
        )
        foreach ($req in $required) {
            if ($normalized -contains $req) { Log "-- Present: $req" }
            else { $errors.Add("Required file missing from the package: $req") }
        }

        # ---- 4. Architecture sanity: no non-x64 native payload in the way
        $badArch = $normalized | Where-Object {
            $_ -match '(^|/)(x86|arm64|arm)(/|$)' -or $_ -match '(?i)(win-x86|win-arm64)'
        }
        if ($badArch) {
            # Dependencies folders for other architectures are a real risk
            # (makes the Store offer a package the device cannot run).
            $errors.Add("Package contains binaries for another architecture: " + (($badArch | Select-Object -First 5) -join ", "))
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
            $wackReport = Join-Path $reportDir "wack-report.xml"
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
                $w = New-Object System.Xml.XmlDocument
                $w.Load($wackReport)
                $overall = ($w.SelectNodes("//REQUIREMENT") | Where-Object { $_.GetAttribute("NAME") -match 'OVERALL' } | Select-Object -First 1)
                if ($overall) { Log "   OVERALL_RESULT: $($overall.GetAttribute('STATUS'))" }
                foreach ($req in $w.SelectNodes("//REQUIREMENT")) {
                    $status = $req.GetAttribute("STATUS")
                    if ($status -and $status -ne "PASS") { Log "   [$status] $($req.GetAttribute('NAME')) - $($req.GetAttribute('DESCRIPTION'))" }
                }
                Copy-Item $wackReport (Join-Path $reportDir "WACK-REPORT.xml") -Force
            } else {
                Log "   WACK produced no report file."
            }
        }
    }
}
finally {
    if (Test-Path $work) { Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue }
}

Log ""
Log "SHA-256 (artifact): $sha256"
if ($errors.Count -gt 0) {
    Log ""
    Log "RESULT: FAILED ($($errors.Count) problem(s))"
    foreach ($e in $errors) { Log "  - $e" }
    $lines | Set-Content $reportPath -Encoding utf8
    Write-Host "Report: $reportPath" -ForegroundColor Red
    exit 1
}

Log "RESULT: PASS (structure, identity, capabilities, architecture, payload)"
$lines | Set-Content $reportPath -Encoding utf8
Write-Host "Report: $reportPath" -ForegroundColor Green
