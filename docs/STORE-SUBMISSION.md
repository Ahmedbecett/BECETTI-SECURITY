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
- [x] **Support email** - `store/privacy-policy.md` now lists
      `ahmedbecetti35@gmail.com` (confirmed by the user) instead of the
      `support@becetti.example` placeholder.
- [x] **Privacy policy hosted at a public HTTPS URL** - live now at:
      `https://github.com/Ahmedbecett/BECETTI-SECURITY/blob/arena/1590a9fd-becetti-security/store/privacy-policy.md`
      (GitHub renders `.md` as formatted HTML; verified publicly reachable,
      no sign-in required, during this session). Two hosting paths were
      attempted and ruled out first - recorded here so they aren't retried:
      - **Vercel**: a project was created and a deployment was attempted
        7 different ways (files-based, git-linked, with/without explicit
        `project_settings`, with/without `root_directory`). Every attempt
        failed with the same Vercel API error - *"The `projectSettings`
        object is required for new projects, but is missing in the
        deployment payload"* - even when `project_settings` was explicitly
        supplied. This is a bug/limitation in the Vercel connector tool's
        first-deployment path, not something fixable from this session. A
        static HTML privacy-policy page was still prepared at
        `store/site/index.html` in case you want to deploy it yourself
        later (`vercel deploy` from the Vercel CLI, or retried through the
        connector once/if that bug is fixed).
      - **GitHub Pages**: `gh api -X POST .../pages` failed with `403
        Resource not accessible by integration` - enabling Pages needs
        repository-admin permission the sandbox's GitHub token doesn't
        have; only you can enable it from **Settings → Pages** in the
        GitHub UI.
      - **Caveat on the current GitHub-blob URL**: it is tied to the
        branch name `arena/1590a9fd-becetti-security`. Once this work is
        merged, **update the Partner Center privacy policy field to point
        at the `main` branch** version instead, e.g.
        `https://github.com/Ahmedbecett/BECETTI-SECURITY/blob/main/store/privacy-policy.md`,
        since a feature branch can be deleted after merging and would
        break the link.
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
2. Partner Center's submission wizard has a dedicated
   **Submission options → Restricted capabilities** step that appears
   specifically because the package declares `runFullTrust`. It asks for a
   free-text justification before the submission can proceed.

   The justification text below was verified against the actual source in
   this repository (not written from assumption) - every PowerShell cmdlet
   and executable named in it is a real call made by
   `src/Becetti.Security.Core/Services/DefenderService.cs`:
   `Get-MpComputerStatus` (status), `Get-MpThreatDetection` (threat list),
   `Get-NetFirewallProfile` (firewall state), `Update-MpSignature` /
   `MpCmdRun.exe -SignatureUpdate` (signature updates), `Set-MpPreference`
   (toggle real-time protection), `Remove-MpThreat` (quarantine/removal),
   and `MpCmdRun.exe -Scan` (Quick/Full/Custom scans). None of these can be
   invoked from an AppContainer-sandboxed process - they require
   `runFullTrust`.

   Suggested justification text (EN), ready to paste as-is:

   > BECETTI SECURITY is a Windows security dashboard that reads and
   > manages Microsoft Defender's real-time protection state. It does not
   > contain its own antivirus engine; it is a front-end for Microsoft
   > Defender. This requires full trust because it invokes the Microsoft
   > Defender command-line scanner (MpCmdRun.exe, for -Scan and
   > -SignatureUpdate) and PowerShell Defender/firewall cmdlets
   > (Get-MpComputerStatus, Get-MpThreatDetection, Get-NetFirewallProfile,
   > Update-MpSignature, Set-MpPreference, Remove-MpThreat), none of which
   > can be called from an AppContainer-sandboxed process. Full trust is
   > used only for this Defender integration, local settings/history
   > storage under %LocalAppData%, and optional outbound HTTPS calls to the
   > app's own cloud API (internetClient) for file-hash reputation lookups
   > and update checks. The app never disables, replaces, or duplicates
   > Defender's protection.

   Arabic version, ready to paste as-is:

   > تطبيق BECETTI SECURITY هو لوحة تحكم أمان لنظام Windows تقرأ وتدير حالة
   > الحماية في الوقت الحقيقي الخاصة بـ Microsoft Defender. لا يحتوي على
   > محرك مضاد فيروسات خاص به؛ إنه واجهة أمامية لـ Microsoft Defender.
   > يتطلب ذلك الثقة الكاملة (full trust) لأنه يستدعي أداة سطر الأوامر
   > الخاصة بـ Microsoft Defender (MpCmdRun.exe لأوامر -Scan و
   > -SignatureUpdate) وأوامر PowerShell الخاصة بـ Defender والجدار الناري
   > (Get-MpComputerStatus، Get-MpThreatDetection، Get-NetFirewallProfile،
   > Update-MpSignature، Set-MpPreference، Remove-MpThreat)، وكل هذه لا
   > يمكن استدعاؤها من عملية معزولة (AppContainer). تُستخدم الثقة الكاملة
   > فقط لهذا التكامل مع Defender، وتخزين الإعدادات والسجل محليًا تحت
   > %LocalAppData%، واستدعاءات HTTPS الصادرة الاختيارية
   > (internetClient) إلى واجهة التطبيق السحابية الخاصة للتحقق من سمعة
   > الملفات (بالبصمة فقط) والتحقق من التحديثات. لا يقوم التطبيق أبدًا
   > بتعطيل Defender أو استبداله أو تكراره.
3. Microsoft's certification team then reviews the app under its normal
   certification process (this can take longer for full-trust desktop
   apps than for sandboxed UWP apps, but it is a well-established,
   commonly-approved pattern - many mainstream desktop apps ship through
   the Store this way: Partner Center's own documentation confirms full
   trust is allowed for Store submission as long as the restricted
   capability is declared and justified). There is nothing to request or
   wait for *before* submitting; the justification is reviewed as part of
   that one certification pass.

## Building the `.msixupload` on Windows (step by step)

This package must be built on a real Windows machine - it cannot be built in
this Linux sandbox (no Windows SDK, no MSBuild-for-UWP, no WinUI 3 toolchain
here). Two supported ways to build it:

### Option A - Visual Studio GUI (recommended, most reliable)

1. Install **Visual Studio 2022** (Community edition is fine) with these
   workloads checked in the Visual Studio Installer:
   - ".NET desktop development"
   - "Universal Windows Platform development"
   - Under "Individual components", make sure **Windows App SDK C#
     Templates** and the **Windows 10/11 SDK** matching
     `10.0.26100.0` (the manifest's `MaxVersionTested`) are installed.
2. Open `Becetti.Security.App.sln` (or the solution containing
   `packaging/Becetti.Security.App.Package/Becetti.Security.App.Package.wapproj`)
   in Visual Studio.
3. In **Solution Explorer**, right-click the
   **Becetti.Security.App.Package** project (the `.wapproj`, not the main
   app project) → **Publish** → **Create App Packages...**.
4. In the wizard:
   - Choose **Microsoft Store under a new app name** or **... under an
     existing app name you've already reserved** - pick the existing
     reservation for `BECETTI SECURITY` if it is already reserved in
     Partner Center, and sign in with the Partner Center account when
     prompted. (If you don't want Visual Studio to associate the project
     with Partner Center at all, choose **Sideloading** instead at this
     step, then manually set `Signing method: Do not sign package` on the
     next screen - the resulting package is still uploadable to Partner
     Center by hand, you just skip the in-IDE account linking.)
   - Version: leave at `1.0.0.0` for the first submission (bump the 3rd
     number, the Build part, for subsequent updates - e.g. `1.0.1.0`).
   - Architecture: check **x64** only (matches the current pipeline).
   - Leave **Generate app bundle: Never** (a single x64 package, no bundle
     needed for a desktop-only app with one architecture).
5. Click **Create**. Visual Studio builds in Release and produces, under
   `packaging\Becetti.Security.App.Package\AppPackages\`, a folder
   containing `BECETTI SECURITY_1.0.0.0_x64.msixupload` (if you picked the
   Store path) - **this exact file is what you upload to Partner Center**.
   If you picked Sideloading + unsigned, you'll get a `.msix` there instead;
   that works too since Partner Center accepts a bare unsigned `.msix` for
   upload as well, not only `.msixupload`.
6. **Do not sign this file manually** and do not point it at the test
   certificate in `local-only/becetti-test-signing-cert/` - Microsoft signs
   it during certification.

### Option B - Build Tools / command line (for CI or no-GUI machines)

Prerequisites: Visual Studio **Build Tools** 2022 with the same two
workloads as above, run from a "Developer PowerShell for VS 2022" prompt
(so `msbuild` is on PATH).

```powershell
.\scripts\package-store.ps1
```

This runs `msbuild` with `UapAppxPackageBuildMode=StoreUpload` and
`AppxPackageSigningEnabled=false`, producing the same unsigned
`.msixupload` under
`packaging\Becetti.Security.App.Package\AppPackages\...\`. Pass
`-Version 1.0.1.0` for a later update. See the script's header comment for
full details.

### After building, before uploading
- Optionally run the **Windows App Certification Kit** (WACK) against the
  built package first - it catches many certification failures (missing
  capabilities, banned APIs, performance issues) before you spend a
  certification cycle finding them. Start it from the Windows SDK's "App
  Certification Kit" shortcut, or `certkit` must be run from a Windows
  machine; it cannot run in this sandbox.
- Upload the `.msixupload` (or `.msix`) file directly in Partner Center
  under your submission's **Packages** step - no extra conversion step.

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

## "The application has failed to start because its side-by-side
## configuration is incorrect" after a successful sideload install

**FIXED as of commit `0372953` and every release after it**: the packaging
pipeline (`.github/workflows/ci.yml`'s `package-msix` job and
`scripts/package-msix.ps1`) now builds with both `SelfContained=true` and
`WindowsAppSDKSelfContained=true`, which bundle .NET 8 and Windows App
Runtime 1.8 directly inside the `.msix`. A tester hit this error for real
(confirmed on a real Windows machine, after the certificate-trust step had
already succeeded), which is what prompted this fix. Releases built before
that commit are still framework-dependent and can still hit this error if
downloaded and sideloaded today - always use the latest `msix-test-*`
release tag, not an older cached download. The rest of this section is
kept for historical reference and in case `WindowsAppSDKSelfContained` ever
needs to be reverted to `false` (e.g. to reduce package size again).

This happens **after** the certificate-trust step above has already
succeeded (Windows accepted the package and shows "Ready!" / lets you
Launch it) - it is a **separate, later** failure: the app's
`Becetti.Security.App.exe` cannot find the **Windows App Runtime 1.8**
framework package on that machine. This is expected and documented
Microsoft behavior for *any* framework-dependent WinUI 3 app installed by
sideloading rather than through the Microsoft Store, not a bug in this
package: `Becetti.Security.App.csproj` intentionally keeps
`SelfContained=false` (so the MSIX stays small and matches the ~70 KB
framework-dependent pattern Microsoft's own WinUI 3 project template
uses), which means `Microsoft.WindowsAppRuntime.1.8` and its `VCLibs`
dependency are **not bundled inside the .msix** - they are expected to
already be present on the machine, or to auto-download from the
Microsoft Store during install. The Microsoft Store does that
automatically for installs it serves itself; a sideloaded, self-signed
install sometimes cannot trigger that same automatic resolution (for
example if Store services are limited, unlicensed, or unreachable on that
device), leaving the exe without its runtime and producing exactly this
"side-by-side configuration is incorrect" error at launch.

**Fix: install the matching Windows App Runtime 1.8 redistributable once
on that machine, before launching the app.** The version must match the
`Microsoft.WindowsAppSDK` NuGet version pinned in
`src/Becetti.Security.App/Becetti.Security.App.csproj` (currently
`1.8.260921001` - Windows App SDK 1.8.12, the final 1.8 servicing
release). Microsoft publishes a direct installer for exactly that version:

- x64: `https://aka.ms/windowsappsdk/1.8/1.8.260921001/windowsappruntimeinstall-x64.exe`
- x86: `https://aka.ms/windowsappsdk/1.8/1.8.260921001/windowsappruntimeinstall-x86.exe`
- arm64: `https://aka.ms/windowsappsdk/1.8/1.8.260921001/windowsappruntimeinstall-arm64.exe`
- Full redistributable (installer + MSIX packages for all architectures):
  `https://aka.ms/windowsappsdk/1.8/1.8.260921001/Microsoft.WindowsAppRuntime.Redist.1.8.zip`

(Source: [Microsoft Learn - Archive of Windows App SDK downloads](https://learn.microsoft.com/en-us/windows/apps/windows-app-sdk/downloads-archive),
"Windows App SDK 1.8" table, version 1.8.12 / 1.8.260921001.)

Download and run the installer matching your CPU architecture (x64 for
almost all PCs) as Administrator, then launch BECETTI SECURITY again - no
reinstall of the `.msix` itself is needed. If the app was built for a
different `Microsoft.WindowsAppSDK` version in the future, re-check that
version's row in the same Microsoft Learn archive page rather than reusing
this URL blindly, since the runtime version must match what the app was
compiled against.

An alternative, more general fix covering the same root cause plus any
missing `VCLibs` dependency on its own:
```powershell
# As Administrator, PowerShell:
Add-AppxPackage -Path .\Microsoft.VCLibs.x64.14.00.Desktop.appx   # if VCLibs itself is also missing
.\windowsappruntimeinstall-x64.exe                                 # installs WindowsAppRuntime 1.8 + its own VCLibs dependency
```

As with the certificate-trust step, this manual install is only needed for
sideloading; an end user installing BECETTI SECURITY from the Microsoft
Store never has to do this - the Store resolves and installs framework
dependencies automatically during the real install.
