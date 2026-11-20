# BECETTI SECURITY — Testing Guide

## Automated tests (run in CI on Windows)
- `tests/Becetti.Security.Core.Tests` — SHA-256 vectors, Defender JSON parsing,
  settings round-trip, event-log ordering, cloud client failure modes
  (not-configured, invalid hash, unreachable host).
- `tests/Becetti.Security.Api.Tests` — health, register/login/me flow, wrong
  password, reputation honesty without a provider, auth enforcement,
  update-check with no releases, version comparison.

Run: `dotnet test Becetti.Security.sln -c Release` (or `scripts/test.ps1`).

## Manual verification checklist (Windows 10/11, real machine)
1. Dashboard: every card shows a measured value or "Unknown" — never a guess.
2. Quick Scan: Defender runs; result matches MpCmdRun output; history records it.
3. Custom scan on a folder; scan of a nonexistent path shows a real error.
4. Real-Time Protection toggle (as admin): state changes and is re-verified.
5. Threat Management: list matches `Get-MpThreatDetection` output in PowerShell.
6. Cloud: with no API URL, cloud pages say "Not configured" (no fake data).
7. Cloud: with the API deployed, sign in, run a reputation check, check updates.
8. Settings: language switch flips layout to RTL; API URL persists.
9. Updates: signature version matches `Get-MpComputerStatus`.

## EICAR controlled test
`scripts/generate-eicar.ps1` creates the standard EICAR test file locally
(never committed). Scan it with Defender on a test machine to confirm the
detection pipeline end-to-end, then delete it. Never use real malware.

## Compatibility
Test on Windows 10 22H2 (17763+) and Windows 11. The app targets
`10.0.17763.0` minimum. Defender cmdlets require Windows 10/11 with Defender
installed (default on both).
