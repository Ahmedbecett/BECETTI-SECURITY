# BECETTI SECURITY

**BECETTI SECURITY** — a genuine Windows security center for Windows 10 and 11,
distributed through the Microsoft Store as an MSIX package. Built with C# /
WinUI 3 / .NET 8. English + Arabic. Premium dark cybersecurity UI.

> **Honest by design.** BECETTI SECURITY uses Microsoft Defender for scanning
> and threat removal — it does not replace Defender, it does not run its own
> antivirus engine, and it never simulates results. If something cannot be
> verified, the app says "Unknown."

## What's inside

- **src/Becetti.Security.App** — WinUI 3 client with ten pages:
  Dashboard, Smart Scan, Real-Time Protection, Cloud Security, Threat
  Management, Privacy & Network, Security History, Updates, Settings, About.
- **src/Becetti.Security.Core** — shared library: real Defender integration
  (cmdlets + MpCmdRun.exe), system info, HTTPS cloud client, settings with
  DPAPI token storage, JSONL event log, SHA-256 hashing, EN/AR localization.
- **src/Becetti.Security.Api** — ASP.NET Core 8 REST API: JWT auth (register,
  login, refresh, logout, me), BCrypt passwords, hashed refresh tokens, file
  reputation (BECETTI DB + optional VirusTotal), update checks, admin endpoints,
  rate limiting, EF Core + PostgreSQL migrations.
- **tests/** — Core unit tests and API integration tests (WebApplicationFactory
  + in-memory SQLite).
- **packaging/** — Windows Application Packaging Project for MSIX output.
- **scripts/** — build, test, MSIX packaging, EICAR test-file generation.
- **docs/** — architecture, API reference, testing guide, implementation report,
  store submission procedure.
- **store/** — privacy policy, app descriptions (EN/AR), minimum requirements.

## Deliverables

1. Complete source code
2. Functional WinUI 3 Windows application
3. Genuine Microsoft Defender integration
4. Genuine security monitoring (live Defender state)
5. Working cloud REST API (authenticated, rate-limited, validated)
6. Working security dashboard
7. Real scan reporting (Quick / Full / Custom via Defender)
8. Genuine threat management (real detections, verified removal)
9. Working application updates (cloud release check + signature updates)
10. Privacy policy
11. Technical documentation
12. Automated tests (Core + API)
13. Release MSIX package (build on Windows; `scripts/package-msix.ps1`)
14. Microsoft Store submission materials

## Build & test

This repo is authored to compile on Windows with the .NET 8 SDK and the
Windows SDK (WinUI 3). There is no .NET SDK available in this sandbox, so
local compilation is delegated to CI / a Windows machine.

```powershell
# Restore
dotnet restore Becetti.Security.sln

# Build (Release, x64)
dotnet build Becetti.Security.sln -c Release --no-restore -p:Platform=x64

# Test (Core + API)
dotnet test Becetti.Security.sln -c Release

# Package as MSIX (Windows + signing certificate required)
./scripts/package-msix.ps1
```

CI runs on every push to `windows-latest`: `restore → build → test` (see
`.github/workflows/ci.yml`).

## Security & honesty rules

- No fake features, no simulated security, no demo data, no false results.
- No BECETTI antivirus engine — Defender does the scanning.
- Files are never uploaded to the cloud; only SHA-256 hashes go to the
  reputation endpoint.
- No secrets embedded in the client (API keys, DB credentials live server-side
  as environment variables).
- TLS certificate validation is never disabled.
- EICAR test file only in controlled environments (`scripts/generate-eicar.ps1`);
  never real malware.

## Store submission

See `docs/STORE-SUBMISSION.md`. Required before submission:
- CI build + tests green on `windows-latest`
- Manual verification on Windows 10 and 11 (`docs/TESTING.md`)
- Code-signing certificate matching the manifest Publisher
- Deployed cloud API + hosted privacy-policy URL (optional for local features)

## License

MIT License (BECETTI 2026). See `LICENSE`.

---

Developed by BECETTI. Your Digital Protection Center.
