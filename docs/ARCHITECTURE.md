# BECETTI SECURITY — Architecture

## Overview

BECETTI SECURITY is a Windows security center built on **Microsoft Defender**
(the supported Windows security engine) plus an optional **BECETTI cloud API**.
The app never runs its own antivirus engine and never invents results.

```
┌─────────────────────────────┐        HTTPS (JWT)        ┌──────────────────────────┐
│  BECETTI SECURITY (WinUI 3) │ ────────────────────────▶ │  BECETTI SECURITY API    │
│  src/Becetti.Security.App   │                           │  src/Becetti.Security.Api  │
│  src/Becetti.Security.Core  │ ◀──────────────────────── │  ASP.NET Core 8 + PostgreSQL│
└──────────────┬──────────────┘                           └──────────────────────────┘
               │  PowerShell Defender cmdlets + MpCmdRun.exe
               ▼
┌─────────────────────────────┐
│  Microsoft Defender (Windows)│  Get-MpComputerStatus, Get-MpThreatDetection,
│  Windows Security APIs       │  Update-MpSignature, Set-MpPreference,
└─────────────────────────────┘  Remove-MpThreat, Get-NetFirewallProfile
```

## Components

### Becetti.Security.Core (net8.0, cross-platform library)
- `DefenderService` — genuine Defender integration via PowerShell cmdlets and
  `MpCmdRun.exe`. JSON parsing is factored into pure, unit-tested methods.
- `SystemInfoService` — OS/registry/drive facts, network + real TLS handshake
  (default certificate validation, never disabled).
- `CloudService` — HTTPS REST client with JWT session handling, honest
  `NOT_CONFIGURED` / `OFFLINE` / `RATE_LIMITED` failures.
- `SettingsService` / `TokenStore` — JSON settings under
  `%LocalAppData%\BecettiSecurity`; tokens protected with DPAPI (CurrentUser).
- `EventLogService` — append-only local history of real events only.
- `FileHashService` — local SHA-256 (files are never uploaded).
- `LocalizationService` — English/Arabic with RTL flow direction.

### Becetti.Security.App (WinUI 3, Windows 10/11)
Ten pages (Dashboard, Smart Scan, Real-Time Protection, Cloud Security,
Threat Management, Privacy & Network, Security History, Updates, Settings,
About), each backed by a view model that calls Core services. No dead buttons:
every control invokes a real operation and surfaces its real result or error.

### Becetti.Security.Api (ASP.NET Core 8)
- JWT auth (register/login/refresh/logout/me), BCrypt password hashing,
  hashed refresh tokens.
- File-reputation endpoint: BECETTI DB cache → VirusTotal (when an API key is
  configured) → honest `unknown / no-provider-configured`.
- Update-check endpoint comparing client versions with published releases.
- Admin endpoints (intel stats, manual intel ingest, release publishing).
- Rate limiting (auth: 10/min/IP, API: 120/min/IP), server-side validation,
  audit logging, EF Core migrations for PostgreSQL.

## Security design
- No secrets in the client: JWT signing key, DB credentials and the VirusTotal
  key live only on the server (environment variables).
- TLS verification is never disabled, in the app or the API.
- Least privilege: elevation is requested only for operations that need it
  (signature updates, real-time toggle, threat removal) and failures are shown.
- Telemetry is opt-in and off by default.

## What is NOT in v1.0
- No VPN, no firewall replacement, no web-protection engine.
- No BECETTI-branded antivirus engine. Scanning is Defender's.
- No cloud account is required to use local features.
