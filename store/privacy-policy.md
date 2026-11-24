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
- BECETTI SECURITY itself does not read or store advertising identifiers.
  The advertising SDK described below may process its own ad identifiers.

## Advertising (MG Ads)
BECETTI SECURITY displays ads through the **MG Ads SDK** provided by
**Beijing Qiyou Lingdong Technology Co., Ltd. (Miracle Games)**.

- Ad units used: a 728x90 banner and a 1920x1080 full-screen ad.
- The SDK may process: information you actively submit, device information
  (device model, operating-system version), network information (network
  type), application information, and ad-interaction data (impressions,
  clicks, ad close).
- Purpose: ad delivery, frequency capping, attribution and revenue reporting.
- The SDK transmits data over HTTPS and applies de-identification measures.
- MG Ads privacy policy: <https://mg-ads.com/privacy.html>
- MG Ads compliance guide:
  <https://doc.ad.mguwp.net/docs/ComplianceGuide/MGPlatformCompliance/MGAdsAggregationAdvertisingPlatformComplianceManagementGuide>

**Your choice:** advertising can be turned off at any time in
Settings -> Advertising -> "Show ads". Turning it off stops the ad host and
removes all ad requests; no security feature depends on it. Ads are also not
started until the first-run setup wizard has been completed.

## Third-party services
- Microsoft Defender (on-device, by Microsoft).
- VirusTotal (server-side reputation lookups, only when the operator has
  configured an API key; hashes only).
- Microsoft Store (distribution and updates, by Microsoft).
- MG Ads / Miracle Games (advertising, by Beijing Qiyou Lingdong Technology
  Co., Ltd.).

## Your choices
- Use the app fully offline: local features work without any account.
- Sign out at any time (Cloud Security page); tokens are deleted locally.
- Turn off advertising in Settings -> Advertising.
- Delete local data by removing `%LocalAppData%\\BecettiSecurity`.

## Contact
Support: ahmedbecetti41@gmail.com
