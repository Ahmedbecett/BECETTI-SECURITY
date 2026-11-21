# Microsoft Store Submission — Release Procedure

## Prerequisites
1. Windows 10/11 machine with .NET 8 SDK, Windows SDK, Visual Studio 2022
   (or the CI pipeline) for the WinUI 3 build.
2. `src/Becetti.Security.App/Package.appxmanifest`'s `Identity/@Publisher`
   is now set to the verified Microsoft Partner Center Windows Publisher ID
   for this account: `CN=A5D5DC31-4A15-4059-8030-D96C51054596` (no longer
   the `CN=BECETTI` placeholder). This value is **not itself a certificate**
   - it is the identity string Partner Center expects. Two distinct paths
   remain, and this document does not claim either is complete yet:
   - **Store submission**: upload the MSIX to Partner Center as-is (signed
     with any cert whose Subject matches the Publisher above, including the
     CI's self-signed test certificate) - Microsoft re-signs the package
     with its own trusted certificate during ingestion. The `Publisher`
     match is what Partner Center validates; it does not require you to
     already own a Microsoft-trusted certificate before uploading.
   - **Direct/enterprise sideloading outside the Store**: requires an
     actual CA-issued (or otherwise already-trusted-on-target-machines)
     code-signing certificate whose Subject matches
     `CN=A5D5DC31-4A15-4059-8030-D96C51054596` exactly. The CI pipeline's
     self-signed certificate is for testing only and is not trusted by
     default on any machine other than one where you manually imported it.
3. A deployed cloud API (optional for Store submission, required for cloud
   features) — see `docs/API.md`.
4. Hosted privacy policy URL (`store/privacy-policy.md`) and support contact.

## Steps
1. `scripts/build.ps1` — build Release x64.
2. `scripts/test.ps1` — run all tests; must pass.
3. Run the manual checklist in `docs/TESTING.md` on Windows 10 and 11.
4. `scripts/package-msix.ps1` — publish + `makeappx pack` + `signtool sign`.
5. Validate: `signtool verify` and install the MSIX on a clean VM.
6. Partner Center: create the app, upload the MSIX, add screenshots
   (capture from the real app), description (`store/description-*.md`),
   privacy policy URL, support email, age rating questionnaire.
7. Submit for certification. All advertised capabilities exist in the build.

## Certification notes (for the reviewer)
- The app integrates with Microsoft Defender via supported interfaces
  (Defender cmdlets + MpCmdRun). It does not replace or disable Defender.
- No telemetry is collected by default; telemetry is opt-in in Settings.
- Cloud features require the API URL configured in Settings; without it the
  app clearly reports cloud as unavailable.
