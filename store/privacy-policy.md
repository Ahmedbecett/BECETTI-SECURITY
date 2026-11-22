# BECETTI SECURITY — Privacy Policy

Effective date: 2026-11-20. Publisher: BECETTI.

## What BECETTI SECURITY does
BECETTI SECURITY is a Windows security center that uses Microsoft Defender
for scanning and threat removal. It does not replace Microsoft Defender.

## Data processed on your device
- Security status and scan results read from Microsoft Defender.
- Your settings, stored locally under `%LocalAppData%\BecettiSecurity`.
- A local history of security events that actually occurred.
- Cloud session tokens, protected with Windows DPAPI.

## Data sent to the BECETTI cloud API (only when you configure it)
- Your account email and password (passwords are hashed with BCrypt on the
  server; plaintext is never stored).
- SHA-256 hashes of files you explicitly choose to check. **Files themselves
  are never uploaded.**
- Your app version, when you check for updates.

## Data never collected
- No telemetry by default. Telemetry is opt-in in Settings and off by default.
- No browsing history, no keystrokes, no screen content, no personal files.
- No advertising identifiers.

## Third-party services
- Microsoft Defender (on-device, by Microsoft).
- VirusTotal (server-side reputation lookups, only when the operator has
  configured an API key; hashes only).
- Microsoft Store (distribution and updates, by Microsoft).

## Your choices
- Use the app fully offline: local features work without any account.
- Sign out at any time (Cloud Security page); tokens are deleted locally.
- Delete local data by removing `%LocalAppData%\BecettiSecurity`.

## Contact
Support: ahmedbecetti41@gmail.com
