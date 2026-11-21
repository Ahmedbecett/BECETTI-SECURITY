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
4. For an actual Partner Center submission, use
   `scripts/package-store.ps1` instead of `package-msix.ps1` — it builds
   the unsigned `.msixupload` format Partner Center expects (Microsoft
   signs it during certification). `scripts/package-msix.ps1` remains the
   self-signed-test-cert path used for direct sideload testing only
   (CI's `package-msix` job) and is not the right artifact to upload to
   the Store.
5. Validate: `signtool verify` and install the MSIX on a clean VM (for the
   sideload/test artifact only — the `.msixupload` is unsigned and is not
   meant to be installed directly).
6. Partner Center: create the app, upload the `.msixupload`, add screenshots
   (capture from the real app), description (`store/description-*.md`),
   privacy policy URL, support email, age rating questionnaire.
7. Submit for certification. All advertised capabilities exist in the build.

## Pre-submission readiness checklist (status as of this commit)

What is already technically ready in this repository:
- [x] `Identity/@Publisher` matches the verified Partner Center Windows
      Publisher ID exactly (`CN=A5D5DC31-4A15-4059-8030-D96C51054596`).
- [x] `Capabilities` are minimal and correctly declared: `runFullTrust`
      (under the `rescap` restricted-capabilities namespace, required
      because Defender integration calls `MpCmdRun.exe` and PowerShell
      Defender cmdlets - a sandboxed/non-full-trust app cannot do this) and
      `internetClient` (cloud API over HTTPS). No other restricted
      capabilities are requested.
- [x] All required tile/logo assets exist at the correct pixel sizes:
      `Square44x44Logo.png` (44x44), `Square71x71Logo.png` (71x71),
      `Square150x150Logo.png` (150x150), `Square310x310Logo.png` (310x310),
      `Wide310x150Logo.png` (310x150), `StoreLogo.png` (50x50).
- [x] `TargetDeviceFamily` covers Windows 10 1809+ through Windows 11
      (`MinVersion=10.0.17763.0`, `MaxVersionTested=10.0.26100.0`).
- [x] Store listing copy ready in both languages: `store/description-en.md`,
      `store/description-ar.md`, `store/requirements.md`.
- [x] Privacy policy drafted: `store/privacy-policy.md` - content is
      accurate to what the app actually does (Defender-backed, optional
      cloud, hashes-only reputation checks, no telemetry by default).
- [x] Self-signed test certificate is isolated to the `package-msix`
      CI job for sideloading test builds only; it is never referenced by,
      or required for, the Store submission path. Store ingestion re-signs
      whatever is uploaded with Microsoft's own trusted certificate,
      regardless of what signed the uploaded file, as long as the
      Publisher string matches (it does).

What still needs a real action before an actual submission can succeed -
none of these can be fabricated or completed from inside a sandboxed CI
environment, they need a human with a Partner Center account and/or a real
Windows machine:
- [ ] **Replace the placeholder support email** in
      `store/privacy-policy.md` (currently `support@becetti.example`) with
      a real, monitored address.
- [ ] **Host the privacy policy at a public URL** for the Partner Center
      submission form. The simplest option that needs no extra
      infrastructure: link directly to the rendered Markdown file on
      GitHub, e.g.
      `https://github.com/Ahmedbecett/BECETTI-SECURITY/blob/<branch>/store/privacy-policy.md`
      (GitHub renders `.md` files as formatted HTML automatically - this is
      commonly accepted by Partner Center). A dedicated GitHub Pages site
      is a cleaner alternative but requires enabling Pages in the repo's
      Settings, which only the repository owner can do.
- [ ] **Real screenshots of the actual running app**, captured on a real
      Windows 10/11 machine after installing a genuine build. These cannot
      be produced here: this sandbox has no Windows runtime, so the WinUI 3
      UI never actually renders anywhere in this environment - any
      "screenshot" generated without a real running app would be a
      fabricated image, which is explicitly out of scope for this project.
- [ ] **Run the Windows App Certification Kit (WACK)** against a Release
      build on a real Windows machine before uploading (catches issues
      Partner Center's own automated certification would otherwise catch
      later, saving a submission cycle). Not strictly required to upload,
      but strongly recommended. This also cannot run inside this sandbox.
- [ ] **Reserve the app name** in Partner Center (Account → create a new
      app submission → reserve `BECETTI SECURITY`) if not already done -
      this is a Partner Center account action.
- [ ] Decide whether to ship a single x64 package (current pipeline) or add
      x86/ARM64 builds bundled into one `.msixbundle` for broader hardware
      coverage. Not a blocker - x64-only is an accepted, complete Store
      submission on its own.

## `runFullTrust` restricted capability - what "approval" actually means

There is no separate, advance approval step for `runFullTrust` outside the
normal Partner Center submission flow. In practice:
1. Declaring `rescap:Capability Name="runFullTrust"` in the manifest (done)
   is itself the formal declaration - Partner Center detects it
   automatically from the uploaded package.
2. Partner Center's submission form then asks you to **justify** each
   declared restricted capability in a free-text box before you can submit.
   Suggested justification text (EN):

   > BECETTI SECURITY is a desktop security companion app that reads and
   > manages Microsoft Defender's real-time protection state. This requires
   > full trust because it invokes Microsoft Defender's own command-line
   > tool (MpCmdRun.exe) and PowerShell Defender cmdlets
   > (Get-MpComputerStatus, Set-MpPreference, Update-MpSignature), neither
   > of which can be called from an AppContainer-sandboxed process. The app
   > does not use full trust for anything beyond Defender integration,
   > local settings storage, and optional HTTPS calls to its own cloud API.

   Arabic version:

   > تطبيق BECETTI SECURITY هو تطبيق أمان لسطح المكتب يقرأ ويدير حالة
   > الحماية في الوقت الحقيقي الخاصة بـ Microsoft Defender. يتطلب ذلك
   > الثقة الكاملة (full trust) لأنه يستدعي أداة سطر الأوامر الخاصة بـ
   > Microsoft Defender نفسها (MpCmdRun.exe) وأوامر PowerShell الخاصة بـ
   > Defender (Get-MpComputerStatus، Set-MpPreference،
   > Update-MpSignature)، وكلاهما لا يمكن استدعاؤهما من عملية معزولة
   > (AppContainer). لا يستخدم التطبيق الثقة الكاملة لأي غرض آخر غير
   > التكامل مع Defender وتخزين الإعدادات محليًا واستدعاءات HTTPS
   > الاختيارية إلى واجهته السحابية الخاصة.
3. Microsoft's certification team then reviews the app under its normal
   certification process (this can take longer for full-trust desktop
   apps than for sandboxed UWP apps, but it is a well-established,
   commonly-approved pattern - many mainstream desktop apps ship through
   the Store this way). There is nothing to request or wait for *before*
   submitting; the justification is reviewed as part of that one
   certification pass.

## After the Store listing goes live

Verifying "install from the Store with no manual certificate step" can only
be done once the listing is actually live and installable, on a real
device - this sandbox cannot simulate the Microsoft Store's own signing and
distribution pipeline. Once you have a live Store link, share it and a
scan of its listing page / any install issue can be reviewed the same way
installer errors were diagnosed above.

## Certification notes (for the reviewer)
- The app integrates with Microsoft Defender via supported interfaces
  (Defender cmdlets + MpCmdRun). It does not replace or disable Defender.
- No telemetry is collected by default; telemetry is opt-in in Settings.
- Cloud features require the API URL configured in Settings; without it the
  app clearly reports cloud as unavailable.

## Error 0x800B010A ("A certificate chain could not be built to a trusted
## root authority") and Publisher showing as "Unknown" when sideloading

This is **expected, correct Windows behavior** for the CI's self-signed TEST
MSIX, not a defect in the package. The signature itself is valid (file
integrity is intact, Publisher inside the package genuinely matches
`CN=A5D5DC31-4A15-4059-8030-D96C51054596`), but the certificate that signed
it is not rooted in any Certificate Authority Windows already trusts. There
are exactly three ways to resolve it, and no fourth shortcut exists that
does not involve either manually trusting a certificate or paying for one
that is already trusted:

1. **Manually trust the test certificate once per machine** (what the
   release's `INSTALL.txt` documents): import `BecettiTestCert.cer` into
   `Cert:\LocalMachine\TrustedPeople` (or Trusted Root), after verifying its
   SHA-256 fingerprint against the one printed in the release notes /
   `INSTALL.txt` with `certutil -hashfile BecettiTestCert.cer SHA256`. This
   does **not** disable Defender or skip signature verification - it tells
   Windows to trust this one specific certificate, the same mechanism IT
   departments use for internal line-of-business apps.
2. **Submit to the Microsoft Store** (see "Steps" above). Microsoft re-signs
   the package with its own trusted certificate on ingestion, so an
   end-user installing from the Store never sees this error or an "Unknown"
   publisher - Windows already trusts Microsoft's own signing root.
3. **Buy a commercial OV/EV code-signing certificate** from a CA already in
   Windows' trusted root store (DigiCert, SSL.com, GlobalSign, Sectigo,
   etc.), with Subject exactly matching the Publisher above, and sign with
   it in place of the self-signed test certificate (point
   `PackageCertificateKeyFile`/`PackageCertificatePassword` at it in
   `scripts/package-msix.ps1` or the CI `package-msix` job). This requires
   real payment and identity verification by the CA; it cannot be
   substituted with anything generated locally or in CI.

### Making the test certificate's fingerprint stable across releases

By default `package-msix` generates a brand-new self-signed certificate on
every CI run, so `BecettiTestCert.cer`'s fingerprint - and therefore the
trust a tester has already granted it - changes on every release. To avoid
forcing a re-trust on every build, generate the certificate **once** and
store it as repository secrets so every CI run reuses it:

```powershell
# On a Windows machine, once:
$basicConstraints = [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($false, $false, 0, $true)
$ekuOids = [System.Security.Cryptography.OidCollection]::new()
[void]$ekuOids.Add([System.Security.Cryptography.Oid]::new("1.3.6.1.5.5.7.3.3", "Code Signing"))
$eku = [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($ekuOids, $true)
$cert = New-SelfSignedCertificate -Subject "CN=A5D5DC31-4A15-4059-8030-D96C51054596" `
  -CertStoreLocation "Cert:\CurrentUser\My" -KeySpec Signature -KeyUsage DigitalSignature `
  -KeyLength 2048 -KeyAlgorithm RSA -HashAlgorithm SHA256 -Extension @($basicConstraints, $eku) `
  -FriendlyName "BECETTI SECURITY test signing certificate" -NotAfter ([System.DateTime]::UtcNow.Date.AddYears(2))
$pw = Read-Host -AsSecureString "Set a PFX password" | ConvertFrom-SecureString -AsPlainText
$pfxBytes = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, $pw)
[System.Convert]::ToBase64String($pfxBytes) | Set-Clipboard   # paste into the PFX_BASE64 secret
```

Then, in the repository's GitHub Settings -> Secrets and variables ->
Actions, add two **repository secrets** (only a repo admin/owner can do
this - a CI job cannot create its own secrets):
- `BECETTI_TEST_SIGNING_PFX_BASE64` — the base64 string above.
- `BECETTI_TEST_SIGNING_PFX_PASSWORD` — the PFX password you chose.

Once both are set, `package-msix` automatically switches to reusing that
exact certificate for every future build (it verifies the Subject matches
before using it), and `INSTALL.txt` / the release notes will show the same
SHA-256/SHA-1 fingerprint on every release until the certificate is
rotated or expires. This certificate is still self-signed and still
requires the one-time manual trust step above on each end-user machine -
only Store submission or a CA-purchased certificate removes that step
entirely.
