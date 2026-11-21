# BECETTI SECURITY — Microsoft Store Readiness Report

Date: 2026-11-20. Repository state: branch `arena/1590a9fd-becetti-security`,
commit `56aea3d` (plus the doc/script additions made alongside this report).

This report distinguishes what has actually been **verified** in this
session (by reading source code, running CI, or querying live tool state)
from what is **drafted but unverified** (text/config prepared but not yet
exercised on a real Windows machine or in a real Partner Center account),
and from what **cannot be done from this sandbox at all**. Nothing below is
stated as "working" or "tested" unless it was concretely checked.

---

## 1. Package identity — VERIFIED, UNCHANGED

| Field | Value | Status |
|---|---|---|
| `Identity/@Name` | `BECETTI.BECETTISECURITY` | Unchanged this session (last touched in commit `46220eb`, before this sub-task began) |
| `Identity/@Publisher` | `CN=A5D5DC31-4A15-4059-8030-D96C51054596` | Unchanged this session; this is the value the user previously confirmed matches their verified Partner Center Windows Publisher ID |
| `Properties/Version` | `1.0.0.0` | Unchanged; valid 4-part version for a first submission |
| `ProcessorArchitecture` | `x64` | Unchanged |

Verified by: `git log --follow -- src/Becetti.Security.App/Package.appxmanifest`
shows no commits touching this file since `46220eb`, i.e. before this
Store-readiness sub-task started. **No identity, publisher, or version
values were changed as part of this work**, per your explicit instruction.

## 2. Capabilities — VERIFIED ACCURATE AGAINST CODE

Manifest declares exactly two capabilities: `runFullTrust` (restricted) and
`internetClient`. Every function named in the drafted `runFullTrust`
justification text was cross-checked against the actual implementation in
`src/Becetti.Security.Core/Services/DefenderService.cs` and found accurate:

| Claimed capability use | Verified in code at |
|---|---|
| `MpCmdRun.exe` (scan + signature update) | `DefenderService.cs` lines ~151, ~178, ~265 |
| `Get-MpComputerStatus` | `DefenderService.cs` line ~90 |
| `Get-MpThreatDetection` | `DefenderService.cs` line ~130 |
| `Get-NetFirewallProfile` | `DefenderService.cs` line ~112 |
| `Update-MpSignature -UpdateSource MicrosoftUpdateServer` | `DefenderService.cs` line ~249 |
| `Set-MpPreference` | `DefenderService.cs` line ~322 |
| `Remove-MpThreat` | `DefenderService.cs` line ~347 |

No capability is declared that the app does not actually use, and no
functionality is claimed in the justification text that the app does not
actually implement. This satisfies your requirement #4 ("لا ادعاءات غير
منفذة").

**Not verified**: that this justification text, once pasted into Partner
Center's real "Submission options → Restricted capabilities" form, will be
accepted by Microsoft's certification reviewers. That can only be confirmed
by actually submitting - no sandbox can simulate Microsoft's review
decision.

## 3. Store assets — VERIFIED

All required manifest tile images exist at the correct pixel dimensions
(verified by parsing each PNG's IHDR chunk directly, since no image library
was available in this sandbox):

`Square44x44Logo.png` 44×44, `Square71x71Logo.png` 71×71,
`Square150x150Logo.png` 150×150, `Square310x310Logo.png` 310×310,
`Wide310x150Logo.png` 310×150, `StoreLogo.png` 50×50.

**Not available / cannot be produced here**: the Store *listing*
screenshots (separate from manifest tiles) must be real captures of the
running app on Windows - see `store/screenshots-shotlist.md` (new this
session) for exactly what to capture and in what order. Zero screenshots
exist yet; this is a hard blocker for submission (Partner Center requires
at least one).

## 4. Packaging pipeline — PARTIALLY VERIFIED

| Artifact | Purpose | Verification status |
|---|---|---|
| `scripts/package-msix.ps1` + CI `package-msix` job | Self-signed test MSIX for **sideload testing only** | **Fully verified, repeatedly, in live CI**: builds, signs, and publishes successfully; fingerprint confirmed stable across multiple releases (`msix-test-1aee00f`, `msix-test-56aea3d`, etc.) |
| `scripts/package-store.ps1` (new this session) | Unsigned `.msixupload` for Partner Center | **Written but NOT executed anywhere** - this sandbox has no Windows SDK/MSBuild-for-UWP toolchain to run it. The MSBuild property names (`UapAppxPackageBuildMode=StoreUpload`, `AppxPackageSigningEnabled=false`) are the documented, standard ones for this build mode, but the script has not produced an actual `.msixupload` file in this session. **This must be run and checked on a real Windows machine before you rely on it.** |
| Visual Studio "Create App Packages" wizard (Option A in `docs/STORE-SUBMISSION.md`) | Same `.msixupload`, GUI path | Documented from Microsoft's own published workflow; **not executed** - requires Visual Studio on Windows, unavailable here |

## 5. Microsoft Store policy research — VERIFIED (current, fetched live this session)

Confirmed directly from `learn.microsoft.com` (fetched this session, not
from training-data memory, since Store policy details change over time):
- MSIX/MSIXUPLOAD submissions do **not** need a CA-trusted certificate; the
  Store re-signs the package after certification. Confirmed by
  `learn.microsoft.com/windows/apps/publish/get-started` and
  `.../store-readiness-checklist`.
- A privacy policy URL is **mandatory** for packaged desktop apps (WinUI 3 /
  Desktop Bridge), even if the app collects no personal data - confirmed by
  the official Store readiness checklist page. This is why requirement #2
  (hosting the privacy policy) is a real blocker, not optional polish.
- Restricted-capability justification happens in a dedicated
  **Submission options → Restricted capabilities** step, triggered
  automatically because `runFullTrust` is declared - confirmed from the
  same checklist page and corroborated by independent real-world examples
  found in public repositories doing the same thing.
- Screenshot requirements (desktop: 1366×768 minimum PNG, 1 required/4+
  recommended/10 maximum) confirmed from
  `.../publish-your-app/msix/screenshots-and-images`.

## 6. Support email and privacy policy hosting — DONE (with one caveat)

- `store/privacy-policy.md` now lists `ahmedbecetti35@gmail.com` (you
  confirmed this is the address to use), replacing the
  `support@becetti.example` placeholder. Verified by re-reading the file.
- **Hosting attempted on Vercel first, and it failed** - not from lack of
  trying. A project was created and a deployment was attempted 7 different
  ways (plain files, git-linked, with explicit `project_settings` in every
  reasonable shape). Every attempt returned the same Vercel API error:
  *"The `projectSettings` object is required for new projects, but is
  missing in the deployment payload"* - even though it was supplied. This
  points to a bug in the Vercel connector tool's handling of a project's
  very first deployment, which cannot be fixed from this session. Reported
  honestly rather than worked around with a fake success.
- **GitHub Pages attempted next, also failed** - `gh api -X POST
  .../pages` returned `403 Resource not accessible by integration`; the
  sandbox's GitHub token does not have the repository-admin scope Pages
  setup requires. Only you can enable it, from the repo's
  **Settings → Pages**.
- **What is actually live right now, verified by fetching it in this
  session**: GitHub renders `store/privacy-policy.md` as a formatted page
  automatically, and the repository is public, so this URL works today,
  with no sign-in:
  `https://github.com/Ahmedbecett/BECETTI-SECURITY/blob/arena/1590a9fd-becetti-security/store/privacy-policy.md`
  This is a real, working, public HTTPS URL - confirmed by fetching it
  and seeing the rendered content with the real support email, not
  assumed. **Caveat**: it points at this feature branch. After this work
  is merged, switch the URL used in Partner Center to the `main`-branch
  version so it survives this branch being deleted later.
- A styled static HTML version was also prepared at `store/site/index.html`
  (bilingual EN/AR, matches the app's dark theme) in case you later want a
  nicer-looking page - e.g. by deploying it yourself through the Vercel
  CLI/dashboard, or once the connector bug above is fixed.

## 7. What this sandbox categorically cannot do

- Run Visual Studio, MSBuild-for-UWP, or the Windows App Certification Kit
  (no Windows runtime in this sandbox).
- Capture real screenshots of the running WinUI 3 app (same reason).
- Create or access your Partner Center account, reserve the app name, fill
  in the submission wizard, or click Submit - all of that requires your own
  Partner Center login and is explicitly **not** going to be done
  automatically, per your instruction not to submit without your review.
- Verify "installs from the Store without any manual certificate step" -
  that can only be checked once the app is actually live in the Store, on
  a real device.

## 8. Summary: ready vs not ready

**Technically ready, verified in this repository:**
- Package identity/publisher/version/capabilities (unchanged, accurate).
- Store tile assets (correct sizes).
- Listing copy in EN/AR (`store/description-*.md`, `store/requirements.md`).
- `runFullTrust` justification text, fact-checked against real code.
- Self-signed test-cert path kept fully separate from the Store path
  (confirmed: `package-msix.ps1`/CI test cert is never referenced by
  `package-store.ps1` or the `.wapproj`'s Store publish settings).
- Real support email in place (`ahmedbecetti35@gmail.com`), confirmed by you.
- Privacy policy live at a real, verified-reachable public HTTPS URL
  (GitHub-rendered Markdown - see §6; Vercel and GitHub Pages were both
  attempted and genuinely failed for reasons outside this session's
  control, not silently skipped).

**Drafted, not yet verified on a real machine/account:**
- `scripts/package-store.ps1` (needs a Windows run).
- The Visual Studio GUI packaging steps (needs Visual Studio).

**Not started / blocking a real submission:**
- Real screenshots (needs a Windows machine with the app actually running).
- Partner Center app name reservation status (needs your confirmation -
  unknown from this sandbox).
- Running the Windows App Certification Kit.
- Re-pointing the privacy policy URL from the feature branch to `main`
  once this work is merged (one-line change in Partner Center, not in
  this repo).

**Explicit scope boundary, per your instruction:** no submission, no
certification request, and no live Store publishing will be triggered from
this environment. Everything above is preparation for your review.
