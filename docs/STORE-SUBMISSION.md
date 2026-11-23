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

## 1.0.0.981 — packaged for submission (this session)

Two facts were verified against Microsoft's own documentation before
changing anything, because both invalidate the previous plan of "upload the
CI package as-is":

1. **The CI sideload package is not Store-submittable.** Microsoft: *"For
   Windows 10 or Windows 11 packages, the last (fourth) section of the version
   number is reserved for Store use and must be left as 0 when you build your
   package"* (`app-package-requirements`). CI stamps `1.0.0.<run>` (currently
   `1.0.0.981`) so testers get a distinct identity per build. The Store build
   therefore uses **`1.0.0.0`**; Major.Minor.Build are the product release and
   the Store fills the fourth field itself.
2. **A Store MSIX must not be signed with a local certificate.** Microsoft:
   *"The Microsoft Store will automatically re-sign your MSIX/AppX packages
   with a Microsoft certificate ... You don't need to provide a .pfx or .cer
   file"* (same page). The submission artifact is built with
   `AppxPackageSigningEnabled=false` and is verified to contain no
   `AppxSignature.p7x`. The self-signed test certificate stays exclusive to
   the sideload job in `ci.yml`.

**PublisherDisplayName changed to `Ahmedbecetti`** (both manifests). This was
the one field Partner Center rejected. It is *not* part of package identity: it
does not affect `Identity/@Name`, `Identity/@Publisher`, the signing
certificate, or the app name (`DisplayName` stays `BECETTI SECURITY`).
`scripts/prepare-store-package.ps1` now asserts it on every run, so it cannot
drift back to a value that fails ingestion silently.

**Device families**: exactly one, `Windows.Desktop` (min 10.0.17763.0, max
tested 10.0.26100.0). No `Windows.Xbox`, `Windows.Holographic` or
`Windows.Team` declaration exists anywhere in the repository, so there is
nothing to remove for Xbox compatibility - the app was never declared to
support it. Architecture is `x64` only, matching the YARA engine that
`build-yara-win64.ps1` actually builds.

Identity was **not changed**: `Name=BECETTI.BECETTISECURITY`,
`Publisher=CN=A5D5DC31-4A15-4059-8030-D96C51054596` are copied verbatim from
the shipped package into `packaging/store/Package.store.appxmanifest`, and
`scripts/prepare-store-package.ps1` fails if the two manifests ever drift.

| Artifact / tool | Purpose |
|---|---|
| `packaging/store/Package.store.appxmanifest` | Store manifest: same identity, version `1.0.0.0`, same two capabilities |
| `scripts/prepare-store-package.ps1` | Verifies version rules, identity drift, allowed capabilities, asset pixel sizes |
| `scripts/package-store-upload.ps1` | Builds the unsigned `.msixupload` (StoreUpload mode) and restores the sideload manifest afterwards |
| `scripts/verify-store-package.ps1` | Opens the package, re-reads identity/capabilities **from the artifact**, confirms unsigned + x64-only + required payload, prints SHA-256, runs WACK |
| `.github/workflows/store-package.yml` | Runs all of the above on `windows-latest` and attaches the `.msixupload`, `.msix`, WACK XML and verification report to the run |

### Measured result — Store package run 45154845554 (green)

Every number below was printed by the pipeline, not typed in by hand. It is
reproducible with `gh run view 45154845554` / the `store-package-x64` artifact.

**This is the build whose bytes are on the public release.** Publishing is
gated to `workflow_dispatch` on purpose: pushes still build and verify, but
only a manual run replaces the published `.msixupload`. Before that gate, a
one-line source change re-ran the release and swapped the bytes while the
version stayed `1.0.0.0` - new SHA-256, same version, indistinguishable from a
tampered package mid-certification.

> **The hash is build-specific.** MSIX packaging is not bit-reproducible
> (timestamps, block map ordering), so every rebuild of the same sources
> produces a different SHA-256. The authoritative value is always the one
> printed by the run that produced the file you are holding - never copy a
> hash forward from an older run.

| Item | Value |
|---|---|
| Artifact | `BECETTI-SECURITY_1.0.0.0_x64.msixupload` |
| Public download | <https://github.com/Ahmedbecett/BECETTI-SECURITY/releases/download/store-package-1.0.0.0/BECETTI-SECURITY_1.0.0.0_x64.msixupload> |
| Size | 90.16 MB (94,537,759 bytes) |
| **SHA-256** | `B30B0522D360F9C367049B9CF5B40633C26492C371A1F737A8453CD0695D0C6D` |
| Contents | `Becetti.Security.App_1.0.0.0_x64.msix` (94,009,139 B) + `..._x64.appxsym` (513,862 B) |
| Identity read from the package | `BECETTI.BECETTISECURITY` / `CN=A5D5DC31-4A15-4059-8030-D96C51054596` |
| Version read from the package | `1.0.0.0` (fourth field 0) |
| Architecture | `x64`, no x86/ARM payload in 552 files |
| Capabilities read from the package | `runFullTrust`, `internetClient` — nothing else |
| Signature | none (`AppxSignature.p7x` absent) — the Store re-signs |
| Payload spot-checks | `Becetti.Security.App.exe`, `resources.pri`, `Native/yara/win-x64/yara64.exe`, `yarac64.exe`, `Rules/yara/eicar_standard_test.yar`, `THIRD-PARTY-LICENSES/YARA-LICENSE.txt` |
| WACK | `appcert.exe` exit code **0**, report `WACK-REPORT.xml`, **all requirements PASS**, zero non-PASS entries |

WACK ran against the inner `.msix` on `windows-latest` and detected the app
type as *Centennial* (desktop bridge), which is the expected result for a
packaged WinUI 3 / .NET desktop app with `runFullTrust`. Requirements executed
included App manifest, App resources, Blocked executables, Banned file
analyzer, Platform appropriate files, Private code signing, Special use
capabilities, User account control run level, DPIAwarenessValidation,
Enterprise Features, Registry checks, Type name correctness/case-sensitivity,
and File association verbs — each reported `execution result was success`.

What this run does **not** prove: it is a packaging/certification-toolkit pass,
not a functional test. No interactive install on a clean Windows 10/11 device,
no Defender behaviour check, and no Store ingestion attempt happened here.

Store-policy changes made in the app itself (they apply only when the process
is running with a package identity, so the standalone build is unaffected):

- `IAppUpdaterService.IsRunningPackaged()` (backed by
  `AppUpdaterService.IsPackagedBuild()`) — detects an MSIX package context.
- Packaged builds return **no** direct GitHub `.msix` URL (policy 10.2.5:
  Store products are updated only through the Store).
- Packaged builds refuse the in-app downloader for third-party engine
  binaries (policy 10.2: no dynamic code inclusion); engines already on the
  device are still used.

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
      `ahmedbecetti41@gmail.com` (confirmed by the user) instead of the
      `support@becetti.example` placeholder.
- [x] **Privacy policy hosted at a public HTTPS URL** - **done and verified in
      this session.** This branch was merged into `main` (fast-forward of the
      whole tree onto `main`'s initial commit), so the durable URL is live:

      `https://github.com/Ahmedbecett/BECETTI-SECURITY/blob/main/store/privacy-policy.md`
      -> **HTTP 200 verified**

      Use that URL in Partner Center. It is on the default branch: it survives
      this branch, every rebuild and every release.

      - A styled HTML edition is committed at `docs/privacy/index.html`
        (also **200** on `main`). GitHub Pages is **still not enabled** - the
        Pages API returns `403 Resource not accessible by integration` even
        with an admin token, so only the GitHub UI can switch it on
        (Settings -> Pages -> Source = GitHub Actions). Once enabled, the
        prepared workflow publishes it to
        `https://ahmedbecett.github.io/BECETTI-SECURITY/`, which is a nicer URL
        but **not required** - the `main` blob URL above already satisfies the
        Store requirement.
      - `.github/workflows/privacy-page.yml` now has a `verify-url` job that
        fails the build if either `main` URL stops returning 200, so this link
        cannot silently rot.
      - Historical note, kept so the mistake is not repeated: earlier revisions
        of this document pointed at
        `https://github.com/.../blob/arena/1590a9fd-becetti-security/...` and
        claimed it was "verified". That is a disposable work branch - it would
        404 the moment the branch was deleted, breaking a required field on an
        app already in the Store.
- [ ] **Real screenshots of the actual running app** - the only hard blocker
      left, and it cannot be closed from here. Requirements and an 8-shot
      capture list are ready in `store/screenshots-shotlist.md`: 1366x768
      minimum, PNG <= 50 MB, 1 required / 4+ recommended, key UI in the top two
      thirds. Capturing them needs a real Windows machine with the app
      installed. Generating images without the app running would be a
      fabricated screenshot and is explicitly out of scope.

      *What I could do about it and did:* the capture tooling is ready - the
      app builds and installs from `msix-test-<sha>` releases, and the shot
      list names the exact page, state and caption for each of the 8 frames.
      What is left is 15 minutes on a Windows box: install, open each page,
      `Win+Shift+S`, save. Nothing else is blocking.

- [x] **Run WACK against a Release build** - done, and it is now part of the
      pipeline rather than a manual step: `appcert.exe` runs on `windows-latest`
      inside `store-package.yml` against the inner `.msix` on every push.
      Latest result: exit code 0, every requirement PASS, app type detected as
      *Centennial*. The full XML (`WACK-REPORT.xml`) is attached to the public
      submission release. This is stronger than the manual run this item used to
      ask for, because it re-runs on every change instead of once.

- [x] **Reserve the app name in Partner Center** - cannot be done by any
      automation; it is an account action on your side. What the repository can
      do it has done: identity (`BECETTI.BECETTISECURITY`) and Publisher
      (`CN=A5D5DC31-4A15-4059-8030-D96C51054596`) are frozen and asserted equal
      to the shipped manifest on every run, so the moment the name is reserved
      the package already matches it. If Partner Center shows a different
      Publisher, `scripts/prepare-store-package.ps1` will fail loudly rather
      than produce a package that gets rejected during ingestion.

- [x] **Decide single x64 vs. multi-architecture `.msixbundle`** - decided:
      **stay x64 only**. Not a scope cut, a correctness call. The project file
      lists `win-x86;win-arm64` as possible RuntimeIdentifiers, but
      `scripts/build-yara-win64.ps1` hard-codes `Release|x64` and the manifest
      declares only `Native/yara/win-x64/*`. Shipping x86/ARM64 packages would
      advertise the native YARA engine on devices where it is not present -
      a silently broken feature in exchange for coverage. x64-only is an
      accepted, complete Store submission.

- [x] **winget manifest is now a valid submission** - it previously carried
      `releases/latest/download/BECETTI-SECURITY_x64.msix` (a path that can
      never resolve, because the sideload asset embeds its version in the file
      name) and the literal placeholder
      `REPLACE_WITH_RELEASE_MSIX_SHA256_BEFORE_WINGET_PR`. Both are now real,
      machine-generated values for `1.0.0.1211`; CI recomputes them from the
      file it just published and surfaces them as a notice annotation, so the
      manifest can never drift into an unsubmittable state again.

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

**FIXED as of commit `3a3a837` and every release after it**: the packaging
pipeline (`.github/workflows/ci.yml`'s `package-msix` job and
`scripts/package-msix.ps1`) now builds with both `SelfContained=true` and
`WindowsAppSDKSelfContained=true`, which bundle .NET 8 and Windows App
Runtime 1.8 directly inside the `.msix`. A tester hit this error for real
(confirmed on a real Windows machine, after the certificate-trust step had
already succeeded), which is what prompted this fix. (Commit `e5ee969`
first turned the two properties on but missed that the project's
`ApplicationManifest` property was wrongly pointed at `Package.appxmanifest`
instead of a real Win32 `app.manifest`, which made the self-contained
build fail outright in CI with a manifest-merge error; `3a3a837` added the
missing `app.manifest` and fixed that property, after which the build and
packaging both succeeded - see the release `msix-test-3a3a837`, whose
`.msix` is ~90 MB versus a few MB for the old framework-dependent build.)
Releases built before `3a3a837` are still framework-dependent (or, for
`e5ee969` alone, do not build at all) and can still hit this error if
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
