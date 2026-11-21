# Required Store screenshots - shot list

These must be **real captures of the actual running app** on a real Windows
10/11 machine. Nothing here can be produced in this sandbox - there is no
Windows runtime to render the WinUI 3 UI, so any image generated without a
genuinely running app would be a fabricated screenshot, which is explicitly
excluded from this project's standards (see repo's "no fabricated/invented
results" principle, also applied to this Store listing).

## Technical requirements (from Microsoft Learn, verified this session)
- Format: `.png`, landscape or portrait, each file ≤ 50 MB.
- Desktop size: **1366×768 minimum**, up to 3840×2160 (4K) supported.
- Count: **1 required, 4+ recommended, 10 maximum** for Desktop.
- Keep key UI and text inside the top two-thirds of the frame (Partner
  Center may overlay text on the bottom third in some listing layouts).
- No extra logos/watermarks/marketing text baked into the screenshot itself.
- Each screenshot can have an optional caption (≤ 200 characters) -
  suggested captions are listed below.
- Capture at Release build, final color/branding (dark cybersecurity theme),
  not Debug. Use Windows' Snipping Tool / `Win+Shift+S`, or Visual Studio's
  built-in screenshot capture during a live-running Store-packaged session.
- Provide the same set of screenshots for the Arabic (RTL) listing if a
  separate `ar` Store listing language is created - capture the app with
  the in-app language switched to Arabic so the RTL layout is shown
  genuinely, not mirrored artificially.

## Suggested shot list (8 screens = covers "4+ recommended" with margin)

1. **Dashboard** (`DashboardPage`) - the main security-status overview:
   antivirus/real-time/firewall/signature/device status cards.
   Caption (EN): "Live security status, read directly from Windows Defender."
2. **Smart Scan** (`ScanPage`) - mid-scan or a completed Quick/Full/Custom
   scan with a real result shown.
   Caption (EN): "Quick, Full, and Custom scans through Microsoft Defender."
3. **Real-Time Protection** (`ProtectionPage`) - Defender state and signature
   version/date, with the elevation-aware controls visible.
   Caption (EN): "Verified real-time protection and signature status."
4. **Threat Management** (`ThreatsPage`) - detections list (can be an empty
   "no threats found" state if the test machine is clean - do not fabricate
   detections).
   Caption (EN): "Real Microsoft Defender detections, with verified removal."
5. **Cloud Security** (`CloudPage`) - optional cloud connection screen,
   showing either a configured state or the honest "not configured" state.
   Caption (EN): "Optional cloud file-reputation checks - hashes only."
6. **Privacy & Network** (`PrivacyPage`) - network/TLS/configuration checks.
   Caption (EN): "Honest network and privacy posture checks."
7. **Security History** (`HistoryPage`) - local event log.
   Caption (EN): "A local history of real security events."
8. **Updates** (`UpdatesPage`) - app update + Defender signature update,
   shown as separate controls.
   Caption (EN): "App updates and Defender signature updates, kept separate."

Optional 9th/10th shots, if capturing extra effort is worthwhile:
9. The same Dashboard in **Arabic, right-to-left** layout, for the Arabic
   Store listing.
10. **Settings** (`SettingsPage`) showing the opt-in telemetry toggle (proof
    of the "no telemetry by default" privacy claim).

## 1:1 App tile icon (300×300, strongly recommended, separate from the
## in-package manifest tiles)
Partner Center lets you upload a dedicated 300×300 PNG for Store display
pages; if omitted, the Store falls back to the icon already in the package
(`Square150x150Logo.png`/`Square310x310Logo.png`, already present and
correctly sized in `src/Becetti.Security.App/Assets/`). Uploading a
dedicated 300×300 image is optional, not a blocker - the in-package icon
is already Store-acceptable.

## Not applicable to this app
- 2:3 Poster art, 1:1 box art, 16:9 Super hero art, and video trailers are
  all optional/"games-focused" or Xbox-only assets - skip them for a
  first submission of a desktop security app, Partner Center does not
  require them here.
