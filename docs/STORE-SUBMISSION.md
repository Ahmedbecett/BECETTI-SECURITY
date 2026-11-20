# Microsoft Store Submission — Release Procedure

## Prerequisites
1. Windows 10/11 machine with .NET 8 SDK, Windows SDK, Visual Studio 2022
   (or the CI pipeline) for the WinUI 3 build.
2. A code-signing certificate whose subject matches the `Publisher` in
   `src/Becetti.Security.App/Package.appxmanifest`. Replace the `CN=BECETTI`
   placeholder with the Partner Center publisher ID.
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
