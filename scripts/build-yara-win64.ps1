<#
.SYNOPSIS
    Obtains and builds the official VirusTotal/yara engine (Windows x64) for BECETTI SECURITY.

.DESCRIPTION
    1. Primary path (source build): Clones https://github.com/VirusTotal/yara at the pinned
       official release tag (default: v4.6.0), restores VirusTotal's native x64 NuGet
       dependencies (OpenSSL + Jansson), builds yara64.exe and yarac64.exe with MSBuild
       (Release|x64), and copies the native binaries plus COPYING (BSD-3-Clause) into
       src/Becetti.Security.App/Native/yara/win-x64/.
    2. Fallback path: If local MSVC/C++ build tools or AppVeyor NuGet feeds are unavailable,
       downloads the official VirusTotal/yara Windows x64 release archive from GitHub Releases
       (https://github.com/VirusTotal/yara/releases/tag/v4.6.0) unless -RequireSourceBuild
       is specified.
    3. Verification: Executes yara64.exe --version, yarac64.exe --version, and compiles all
       bundled .yar rules in src/Becetti.Security.App/Rules/yara/ to verify the native engine
       operates end-to-end on Windows x64.
#>
[CmdletBinding()]
param(
    [string]$YaraVersion = "4.6.0",
    [string]$ReleaseAssetName = "yara-4.6.0-2443-win64.zip",
    [string]$OutputDir = "",
    [switch]$RequireSourceBuild,
    [switch]$SkipSourceBuild
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($OutputDir)) {
    $OutputDir = Join-Path $repoRoot "src\Becetti.Security.App\Native\yara\win-x64"
}
$rulesDir = Join-Path $repoRoot "src\Becetti.Security.App\Rules\yara"
$licenseSrc = Join-Path $repoRoot "THIRD-PARTY-LICENSES\YARA-LICENSE.txt"

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

$workDir = Join-Path ([System.IO.Path]::GetTempPath()) ("becetti-yara-build-" + [System.Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $workDir | Out-Null

$builtFromSource = $false

function Find-MsBuild {
    $cmd = Get-Command msbuild.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }

    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vswhere) {
        $found = & $vswhere -latest -requires Microsoft.Component.MSBuild -find "MSBuild\**\Bin\MSBuild.exe" | Select-Object -First 1
        if ($found -and (Test-Path $found)) { return $found }
    }
    return $null
}

function Find-NuGet {
    $cmd = Get-Command nuget.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }

    $localNuget = Join-Path $workDir "nuget.exe"
    Write-Host "Downloading nuget.exe for native C++ package restore..."
    Invoke-WebRequest -Uri "https://dist.nuget.org/win-x86-commandline/latest/nuget.exe" -OutFile $localNuget -UseBasicParsing
    return $localNuget
}

function Try-BuildFromSource {
    $msbuild = Find-MsBuild
    if (-not $msbuild) {
        Write-Warning "MSBuild was not found on this machine; cannot build YARA from C source."
        return $false
    }

    $srcDir = Join-Path $workDir "yara-src"
    $tag = "v$YaraVersion"
    Write-Host "Cloning official VirusTotal/yara ($tag)..."
    git clone --depth 1 --branch $tag https://github.com/VirusTotal/yara.git $srcDir
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "git clone of VirusTotal/yara $tag failed."
        return $false
    }

    $slnPath = Join-Path $srcDir "windows\vs2019\yara.sln"
    if (-not (Test-Path $slnPath)) {
        Write-Warning "Expected Visual Studio solution not found at $slnPath."
        return $false
    }

    $nuget = Find-NuGet
    Write-Host "Restoring native YARA NuGet packages (OpenSSL x64 + Jansson x64)..."
    & $nuget restore $slnPath -ConfigFile (Join-Path $srcDir "windows\vs2019\NuGet.Config")
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "NuGet restore for YARA native dependencies failed."
        return $false
    }

    # Try v143 (VS 2022) first, then v142 (VS 2019)
    foreach ($toolset in @("v143", "v142")) {
        Write-Host "Building VirusTotal/yara (Release|x64, PlatformToolset=$toolset)..."
        & $msbuild $slnPath /p:Configuration=Release /p:Platform=x64 /p:PlatformToolset=$toolset /p:WindowsTargetPlatformVersion=10.0 /m /v:minimal
        if ($LASTEXITCODE -eq 0) {
            $yaraExe = Get-ChildItem -Path (Join-Path $srcDir "windows\vs2019") -Recurse -Filter "yara64.exe" | Select-Object -First 1
            $yaracExe = Get-ChildItem -Path (Join-Path $srcDir "windows\vs2019") -Recurse -Filter "yarac64.exe" | Select-Object -First 1
            if ($yaraExe -and $yaracExe) {
                Copy-Item -Force $yaraExe.FullName (Join-Path $OutputDir "yara64.exe")
                Copy-Item -Force $yaracExe.FullName (Join-Path $OutputDir "yarac64.exe")
                $copying = Join-Path $srcDir "COPYING"
                if (Test-Path $copying) {
                    Copy-Item -Force $copying (Join-Path $OutputDir "COPYING")
                }
                Write-Host "Successfully built official YARA $YaraVersion x64 from source ($toolset)."
                return $true
            }
        }
    }

    Write-Warning "MSBuild source build of VirusTotal/yara did not succeed with available C++ toolsets."
    return $false
}

function Download-OfficialRelease {
    $url = "https://github.com/VirusTotal/yara/releases/download/v$YaraVersion/$ReleaseAssetName"
    $zipPath = Join-Path $workDir $ReleaseAssetName
    $extractDir = Join-Path $workDir "official-release"

    Write-Host "Downloading official VirusTotal/yara Windows x64 release: $url"
    Invoke-WebRequest -Uri $url -OutFile $zipPath -UseBasicParsing
    Expand-Archive -Path $zipPath -DestinationPath $extractDir -Force

    $yaraExe = Get-ChildItem -Path $extractDir -Recurse -Filter "yara64.exe" | Select-Object -First 1
    $yaracExe = Get-ChildItem -Path $extractDir -Recurse -Filter "yarac64.exe" | Select-Object -First 1
    if (-not $yaraExe -or -not $yaracExe) {
        throw "Official release archive did not contain yara64.exe and yarac64.exe."
    }

    Copy-Item -Force $yaraExe.FullName (Join-Path $OutputDir "yara64.exe")
    Copy-Item -Force $yaracExe.FullName (Join-Path $OutputDir "yarac64.exe")
    if (Test-Path $licenseSrc) {
        Copy-Item -Force $licenseSrc (Join-Path $OutputDir "COPYING")
    }
    Write-Host "Installed official VirusTotal/yara $YaraVersion Windows x64 binaries to $OutputDir."
}

try {
    if (-not $SkipSourceBuild) {
        $builtFromSource = Try-BuildFromSource
    }

    if (-not $builtFromSource) {
        if ($RequireSourceBuild) {
            throw "Source build of VirusTotal/yara failed and -RequireSourceBuild was specified."
        }
        Download-OfficialRelease
    }

    $yaraBin = Join-Path $OutputDir "yara64.exe"
    $yaracBin = Join-Path $OutputDir "yarac64.exe"

    if (-not (Test-Path $yaraBin) -or -not (Test-Path $yaracBin)) {
        throw "Native YARA binaries missing in $OutputDir."
    }

    $yaraVer = (& $yaraBin --version).Trim()
    $yaracVer = (& $yaracBin --version).Trim()
    Write-Host "Verified yara64.exe version:  $yaraVer"
    Write-Host "Verified yarac64.exe version: $yaracVer"

    if (Test-Path $rulesDir) {
        $ruleFiles = Get-ChildItem -Path $rulesDir -Include *.yar,*.yara -File -Recurse
        foreach ($rf in $ruleFiles) {
            $tmpOut = Join-Path $workDir ($rf.BaseName + ".yarc")
            & $yaracBin $rf.FullName $tmpOut
            if ($LASTEXITCODE -ne 0) {
                throw "Bundled YARA rule failed compilation: $($rf.FullName)"
            }
            Write-Host "Validated bundled rule: $($rf.Name)"
        }
    }

    $origin = if ($builtFromSource) { "Built from official VirusTotal/yara v$YaraVersion source (MSVC x64)" } else { "Official VirusTotal/yara v$YaraVersion Windows x64 release" }
    $metaPath = Join-Path $OutputDir "yara-build-info.json"
    @{
        version = $yaraVer
        architecture = "win-x64"
        source = "https://github.com/VirusTotal/yara"
        license = "BSD-3-Clause"
        origin = $origin
        builtAtUtc = [DateTime]::UtcNow.ToString("o")
        yara64Sha256 = (Get-FileHash -Algorithm SHA256 $yaraBin).Hash
        yarac64Sha256 = (Get-FileHash -Algorithm SHA256 $yaracBin).Hash
    } | ConvertTo-Json -Depth 3 | Set-Content -Path $metaPath -Encoding utf8

    Write-Host "YARA Windows x64 engine ready: $OutputDir ($origin)"
}
finally {
    if (Test-Path $workDir) {
        Remove-Item -Recurse -Force $workDir -ErrorAction SilentlyContinue
    }
}
