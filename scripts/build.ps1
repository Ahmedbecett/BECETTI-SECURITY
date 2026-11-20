# Builds the full solution (Release, x64). Run on Windows with .NET 8 SDK.
$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
Set-Location $root

Write-Host "Restoring..."
dotnet restore Becetti.Security.sln

Write-Host "Building (Release, x64)..."
dotnet build Becetti.Security.sln -c Release --no-restore -p:Platform=x64

Write-Host "Build succeeded."
