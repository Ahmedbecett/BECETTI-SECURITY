# BECETTI SECURITY — Minimum Requirements (Store listing)

- OS: Windows 10 version 1809 (build 17763) or later, Windows 11
- Architecture: x64 (x86 and ARM64 builds produced by the same pipeline)
- Microsoft Defender: installed (default on Windows 10/11)
- Internet: required for cloud features and signature updates; local
  features work offline
- Disk: ~150 MB installed
- Display: any resolution; layout is responsive

## Permissions / capabilities
- `runFullTrust` (desktop bridge) — required for Defender integration
  (MpCmdRun + Defender cmdlets). Declared in the manifest.
- `internetClient` — cloud API communication over HTTPS.

## Data safety (Store declaration summary)
- No telemetry by default (opt-in only).
- No personal data collected without an account; account data (email,
  hashed password) only when the user signs in.
- File hashes only for reputation checks; files are never uploaded.
