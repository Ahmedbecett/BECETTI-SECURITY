# Security Policy — BECETTI SECURITY

## Supported Versions

| Version | Supported | Notes |
| :--- | :---: | :--- |
| Latest `x64` MSIX Release | ✅ Yes | Automatically verified via GitHub Actions CI + In-App Auto-Updater |
| Older pre-release snapshots | ❌ No | Please update via **Global Intel & Radar → Auto-Updater** or GitHub Releases |

## Security Architecture Commitments

1. **Zero Simulation / Verifiable Telemetry**: Every detection, firewall rule, registry state, YARA scan result, and threat feed match comes directly from Windows APIs, official VirusTotal YARA x64 binaries, or live public threat intelligence feeds (`abuse.ch`).
2. **Encrypted Quarantine Vault**: Quarantined artifacts are encrypted at rest using **AES-256-GCM** with random nonces and SHA-256 integrity verification on restore.
3. **Privacy-Preserving Password Checks**: Password breach checks use the **HaveIBeenPwned k-Anonymity model** — only the first 5 hex characters of the SHA-1 hash leave the device; raw passwords are never transmitted or stored.
4. **No Embedded Cloud Secrets**: The BECETTI AI backend proxy holds provider API keys exclusively on server-side Vercel environment variables, never in the Windows MSIX binary or repository.
5. **Reversible Hardening & Privacy Controls**: Windows Hardening Auto-Fix and Windows Privacy & Anti-Telemetry Hardener expose explicit status verification and reversible controls (with optional Windows System Restore Point creation).

## Reporting a Vulnerability

If you discover a security vulnerability in **BECETTI SECURITY** (desktop app, YARA integration, quarantine vault, or BECETTI AI backend):

1. **Do NOT open a public GitHub issue** with exploit details.
2. Report it privately using **GitHub Security Advisories** (`Security` tab → `Report a vulnerability`) on `Ahmedbecett/BECETTI-SECURITY`, or contact the maintainer directly via the app's **Contact** page.
3. Include:
   - Affected component and version/commit hash
   - Clear reproduction steps or proof-of-concept
   - Potential security impact and suggested remediation (if known)

### Response Targets
- **Initial acknowledgement**: within 48 hours
- **Triage & severity assessment**: within 5 business days
- **Fix & signed MSIX release**: prioritized based on CVSS severity

Thank you for helping keep **BECETTI SECURITY** and the Windows open-source community safe.
