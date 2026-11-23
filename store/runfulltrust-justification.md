# Restricted capability justification — `runFullTrust`

Field in Partner Center: **Submission options → Restricted capabilities →
`runFullTrust`**. The text below is written to be pasted in as-is. Every claim
in it is traceable to a file in this repository; if the app's behaviour
changes, update it rather than leaving a stale justification (a claim the
certification reviewer cannot reproduce is worse than a shorter one).

---

## Short version (if the field is length-limited)

BECETTI SECURITY is a packaged Win32 desktop application (WinUI 3 / .NET 8,
`EntryPoint="Windows.FullTrustApplication"`). `runFullTrust` is the standard,
Microsoft-documented requirement for every Desktop Bridge / MSIX-packaged
desktop app — without it the packaged executable cannot start. The app's
entire purpose is to read and act on local Windows security state, which is
only possible from a full-trust process: it invokes Microsoft Defender's own
`MpCmdRun.exe` scanner and Defender PowerShell cmdlets, enumerates Security
event logs, and reads/writes documented Windows security registry keys. It
does not sandbox-escape, does not install services or drivers, and does not
elevate itself; any action that needs administrator rights asks Windows for
consent through the standard UAC prompt, triggered by the user's click. No
other restricted capability is requested.

---

## Full version

### 1. What the capability is used for

`runFullTrust` (restricted capability, `rescap` namespace) is declared because
this product is a **desktop application packaged with MSIX**, not a UWP app.
The manifest declares:

```xml
<Application Id="App"
  Executable="Becetti.Security.App.exe"
  EntryPoint="Windows.FullTrustApplication">
```

A `Windows.FullTrustApplication` entry point cannot launch from a package
manifest without `runFullTrust`. There is no reduced-trust equivalent: a UWP
app-hosted process cannot call `Process.Start` on system security tools, read
the Security event log, or access the registry paths this product audits.

### 2. Which concrete Windows APIs need full trust

Everything below runs **locally on the user's device**; the app has no server
component that receives device data.

| Feature (user-visible) | Windows interface actually called | Why full trust is required |
|---|---|---|
| Defender status, threat history, on-demand/full scan, signature update | `MpCmdRun.exe` (Defender's own command-line scanner) and Defender PowerShell cmdlets: `Get-MpComputerStatus`, `Get-MpThreatDetection`, `Update-MpSignature`, `Set-MpPreference`, `Remove-MpThreat` (`src/Becetti.Security.Core/Services/DefenderService.cs`) | Launching system executables and running CIM/PowerShell cmdlets is a full-trust operation; a UWP sandbox cannot start `MpCmdRun.exe` |
| Security event log review / local SIEM | `Get-WinEvent` / Windows Event Log APIs over the Security and System channels | Reading the Security log requires full trust (and, for some channels, elevation) |
| Windows hardening audit & one-click fixes | Documented registry values under `HKLM\SYSTEM\CurrentControlSet`, `HKLM\SOFTWARE\Policies\Microsoft`, `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion` (UAC, SMBv1, RDP/NLA, Controlled Folder Access, Firewall, telemetry switches) | Writing machine-wide security policy is a full-trust, elevation-gated operation |
| Firewall blocking of a connection/app | `netsh advfirewall` / Windows Firewall APIs | Requires full trust and administrator consent |
| Quarantine & vault | Files under the app's own `%LOCALAPPDATA%` data directory, AES-256-GCM encryption keys via Windows DPAPI | Local file and DPAPI access from the packaged process |
| USB / driver / startup / scheduled-task inventory | WMI (`Win32_PnPSignedDriver`), `schtasks.exe`, registry Run keys, `Get-Service` | Enumerating and creating machine-level tasks/services is full trust |
| Open-source engine inventory (YARA, ClamAV, YARA-X, CAPA) | `Process.Start` of the bundled `yara64.exe`/`yarac64.exe` and of any engine binaries already installed on the device | Executing local binaries is full trust; the app **does not download** them in the Store build (see §5) |

### 3. What the app does NOT do

These points matter to reviewers because they bound the blast radius of a
full-trust process:

- **Does not install or run a Windows service or a kernel driver.** There is no
  `windows.service`, no `windows.driver` extension, no `driver` capability in
  the manifest. All scanning is on-demand or user-scheduled.
- **Does not replace Microsoft Defender.** It calls Defender's own supported
  interfaces and reports Defender's verdicts. It never maintains an independent
  antivirus database, never disables Defender, and never uploads files.
- **Does not self-elevate silently.** When an operation needs administrator
  rights, `DefenderService.RestartElevated()` calls
  `Process.Start(new ProcessStartInfo { Verb = "runas" })`, i.e. the standard
  Windows UAC consent dialog the user must approve.
- **Does not start at boot by stealth.** No startup task, no service, no
  bootstrapper is registered by the package.
- **Does not exfiltrate device data.** Telemetry is off unless the user turns it
  on; cloud features are optional and, when used, send only what the feature
  needs (e.g. a URL, a domain, or a file **hash** for reputation — never file
  contents).
- **Does not download and execute code at runtime in the Store build.** See §5.

### 4. Data handling

| Data | Where it goes |
|---|---|
| Scan results, settings, quarantine metadata | Local `%LOCALAPPDATA%\BecettiSecurity` only |
| Cloud AI triage text the user submits (alerts, URLs, scripts) | BECETTI's own Vercel API (`becetti-ai-backend.vercel.app`) — optional, user-initiated |
| File reputation checks | SHA-256 hash only, to the configured reputation service |
| Account tokens (optional sign-in) | Protected locally with Windows DPAPI |

The privacy policy (`store/privacy-policy.md`) is the authoritative, published
description; the app must not collect anything that page does not disclose.

### 5. Store-policy alignment implemented in the same build

Two behaviours that would otherwise conflict with the Store policies a
full-trust app is held to are disabled in any packaged build, in code, not just
in documentation:

- **Policy 10.2.5 (install/update only through the Store).** In a packaged
  build the in-app updater returns no direct `.msix` download URL; the app
  never offers a GitHub installer as its own update path.
  `AppUpdaterService.IsPackagedBuild()` gates this
  (`src/Becetti.Security.Core/Services/AppUpdaterService.cs`).
- **Policy 10.2 (no dynamic inclusion of code).** In a packaged build the
  in-app downloader for third-party engine binaries (ClamAV / YARA-X / CAPA) is
  refused with an explicit message; engines already present on the device are
  still detected and used, and only the **download** step is blocked
  (`MultiEngineAvService.InstallOrUpdateOpenSourceEngineAsync`,
  error code `STORE_POLICY_RESTRICTED`).

Bundled native binaries are static payload of the package: the official
VirusTotal `yara64.exe` / `yarac64.exe` (BSD-3-Clause, noticed in
`THIRD-PARTY-LICENSES/YARA-LICENSE.txt`) and the 43 built-in YARA rules under
`Rules/yara/`. Nothing else is fetched.

### 6. Why no less-privileged design is possible

The product's core promise is to report and act on **real** Windows security
state — Defender status, hardening state, firewall state, event logs, USB and
driver inventory. Windows exposes those through processes, WMI, the registry,
the event log and Defender's own command-line tool, all of which require a
full-trust (and often elevated) context. A UWP-hosted app cannot call any of
them, so a packaged desktop app with `runFullTrust` is the only architecture
that delivers the described functionality — which is exactly the case
`runFullTrust` exists for.

### 7. Reviewer reproduction notes

1. Install the package from the submission; it starts with no Internet access.
2. Open **Dashboard → Microsoft Defender Status**: values come from
   `Get-MpComputerStatus` on the reviewer's own machine; they change when
   Defender's state changes, and are never sampled/hard-coded.
3. Open **EDR → Persistence Hunter**: lists real scheduled tasks, services,
   Winlogon/IFEO/AppInit values present on that machine.
4. Click any action that needs administrator rights, e.g. **Hardening →
   Apply**: Windows shows the standard UAC prompt; declining leaves the system
   unchanged.
5. With no network, every local feature still works; cloud-only features show
   an explicit offline state instead of a fabricated result.
