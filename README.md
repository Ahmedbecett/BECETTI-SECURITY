<div align="center">

# 🛡️ BECETTI SECURITY

### Enterprise-Grade Windows x64 Endpoint Protection, Native YARA v4.6.0 & Global Threat Intelligence Suite

**100% Real Windows APIs · Zero Simulation · Open-Source · 6 Global Languages**

[![Official Website](https://img.shields.io/badge/Official_Website-becetti--ai--backend.vercel.app-2563EB?style=for-the-badge&logo=vercel)](https://becetti-ai-backend.vercel.app)
[![GitHub Releases](https://img.shields.io/github/v/release/Ahmedbecett/BECETTI-SECURITY?include_prereleases&style=for-the-badge&color=10B981&label=Windows%20x64%20MSIX)](https://github.com/Ahmedbecett/BECETTI-SECURITY/releases)
[![Build & Test](https://img.shields.io/github/actions/workflow/status/Ahmedbecett/BECETTI-SECURITY/ci.yml?style=for-the-badge&label=CI%20Build%20%26%20MSIX)](https://github.com/Ahmedbecett/BECETTI-SECURITY/actions)
[![Languages](https://img.shields.io/badge/Languages-EN%20%C2%B7%20AR%20%C2%B7%20FR%20%C2%B7%20ES%20%C2%B7%20DE%20%C2%B7%20TR-38BDF8?style=for-the-badge)](src/Becetti.Security.App/Strings)
[![Security Policy](https://img.shields.io/badge/Security-SECURITY.md-F59E0B?style=for-the-badge)](SECURITY.md)

</div>

---

## 🌍 What Makes BECETTI SECURITY Global & Enterprise-Grade?

**BECETTI SECURITY** is a native **WinUI 3 (.NET 8, Windows 10/11 x64)** cybersecurity suite engineered under one unbreakable covenant: **every scan, detection, firewall rule, threat feed indicator, registry audit, and update check is 100% real and verifiable — never simulated.**

### 🔥 Core Global Architecture

| Pillar | Real Capabilities |
| :--- | :--- |
| **🌐 Global Threat Intel & GeoIP Radar** | Live **abuse.ch** feeds (**Feodo Tracker** C2 IPs, **URLhaus** malware domains, **MalwareBazaar** SHA-256 hashes) with offline disk cache, instant IOC lookup, and **Live Outbound GeoIP Radar** (Country / ASN / ISP + 1-Click Windows Firewall App Blocker) |
| **🎯 MITRE ATT&CK Enterprise Framework** | **24 Enterprise ATT&CK techniques** automatically tagged across YARA, Persistence Hunter, Script Auditor, DLL Inspector, Ransomware Canary, ARP Guard, and Threat Feed detections + interactive coverage matrix |
| **🧬 Official Native YARA v4.6.0 Engine** | Bundled official VirusTotal `yara64.exe` / `yarac64.exe` x64, Real-Time Folder Guard (`FileSystemWatcher`), Live Process Memory Scanner, PE Entropy & Authenticode Forensics, **AES-256-GCM Encrypted Quarantine Vault**, and AI YARA Rule Studio |
| **🛡️ Deep EDR & 1-Click Windows Hardening** | Deep Persistence Hunter (Scheduled Tasks, Services, Winlogon, IFEO, AppInit_DLLs), Hosts/DNS Hijack Guard (1-click Cloudflare `1.1.1.2` / Quad9 `9.9.9.9`), Camera & Mic Live Auditor, PowerShell Base64 `-EncodedCommand` Decoder, Phishing & Homograph URL Inspector, SHA-256 File Integrity Monitor (FIM), and 1-Click Hardening Auto-Fix with Restore Point |
| **🔒 Windows Privacy & Anti-Telemetry Hardener** | 6 real, reversible Windows Registry privacy controls (Diagnostic Telemetry, Advertising ID, Tailored Experiences, Windows Error Reporting, Recall/Activity History, Bing Start Search) |
| **🔍 Proactive Defense & Forensics** | Browser Extensions Risk Auditor (Chrome, Edge, Brave, Firefox), Winget Software Patch Manager, Wi-Fi & ARP Spoofing / MITM Guard, Live Process DLL Inspector, DoD 5220.22-M Secure File Shredder, HaveIBeenPwned **k-Anonymity** Password Breach Checker, and 1-Click Forensic Evidence `.ZIP` Bundle |
| **🤖 BECETTI AI Copilot** | **AI Executive Security Briefing** (readable + spoken aloud) directly on the Dashboard + 1-click **"Ask BECETTI AI"** triage on alerts, URLs, extensions, DLLs, and scripts |
| **🌐 6 Global Languages + Onboarding + Auto-Updater** | Instant live switching across **English (`en-US`), العربية RTL (`ar-SA`), Français (`fr-FR`), Español (`es-ES`), Deutsch (`de-DE`), Türkçe (`tr-TR`)**, 3-step First-Run Onboarding Wizard, `Ctrl+K` Command Palette, Windows Hello / PIN Anti-Tamper Lock, System Tray background host, and **GitHub Releases Auto-Updater** |

---

## 📦 Installation (Windows 10 / 11 x64)

### Option 1: Official Signed MSIX Package (Recommended)
1. Visit **[Official Website](https://becetti-ai-backend.vercel.app)** or **[GitHub Releases](https://github.com/Ahmedbecett/BECETTI-SECURITY/releases)** — the website's download button always resolves to the numerically newest signed MSIX (it does not rely on GitHub's `latest` alias, which is not used for CI builds).
2. Download the latest `BECETTI-SECURITY_*_x64.msix` package (and `BecettiTestCert.cer` for sideloading test builds — see `INSTALL.txt` inside the release).
3. Launch **BECETTI SECURITY** and complete the 3-step First-Run Setup Wizard.

### Option 2: Winget Manifest Ready
A clean Winget community package manifest template is maintained at [`packaging/winget/Becetti.Security.yaml`](packaging/winget/Becetti.Security.yaml).

### Option 3: Build from Source
Requirements: **Windows 10/11 x64**, **.NET 8 SDK**, **Windows App SDK 1.8**.
```powershell
dotnet restore src/Becetti.Security.App/Becetti.Security.App.csproj
dotnet test tests/Becetti.Security.Core.Tests/Becetti.Security.Core.Tests.csproj -c Release
dotnet build src/Becetti.Security.App/Becetti.Security.App.csproj -c Release -p:Platform=x64
```

---

## 🗂️ Repository Structure

- `src/Becetti.Security.Core/` — Platform services, YARA orchestration, EDR/Hardening, MITRE ATT&CK, `abuse.ch` Threat Feeds, GeoIP Radar, Privacy Hardener, Auto-Updater, Localization (6 languages)
- `src/Becetti.Security.App/` — WinUI 3 Obsidian Carbon & Cyber Sapphire desktop application + `.resw` catalogs (`en-US`, `ar-SA`, `fr-FR`, `es-ES`, `de-DE`, `tr-TR`)
- `tests/Becetti.Security.Core.Tests/` — Comprehensive xUnit test suite covering Core engines, EDR, Hardening, Forensics, Localization parity, and Global Wave services
- `backend/becetti-ai/` — Vercel-hosted BECETTI AI backend proxy + Official 6-language Global Website (`https://becetti-ai-backend.vercel.app`)
- `packaging/winget/` — Official Winget package manifest

---

## 🔐 Responsible Security Disclosure

Please review [`SECURITY.md`](SECURITY.md) for vulnerability reporting guidelines, cryptographic standards, and our zero-simulation verification policy.
