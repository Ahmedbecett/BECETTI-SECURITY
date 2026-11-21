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
