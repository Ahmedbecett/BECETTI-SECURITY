# ⬇️ Download BECETTI SECURITY

Choose the file that matches what you need. **The second one is what most
people want** — it is the only one that installs on a normal Windows PC.

---

## 1. Microsoft Store submission package

> **For Partner Center upload only. It does NOT install on a PC.**

**[⬇ Download the Store package (.msixupload)](https://github.com/Ahmedbecett/BECETTI-SECURITY/releases/download/store-package-1.0.0.0-pdn2/BECETTI-SECURITY_1.0.0.0_x64.msixupload)**

| | |
|---|---|
| File | `BECETTI-SECURITY_1.0.0.0_x64.msixupload` |
| Size | 90.16 MB |
| SHA-256 | `09AE8CE6B5F6A4007EA5F030A631D35B9B9E65710C8938580954F53C9682D3B6` |
| Signed | No — Microsoft re-signs it after certification |
| Package identity | `Ahmedbecetti.BECETTISECURITY` |
| Publisher | `CN=A5D5DC31-4A15-4059-8030-D96C51054596` |

This is deliberately unsigned. Upload it at
**Partner Center → your app → Packages**. It is not a file you double-click.

> **Only this build is accepted.** Partner Center rejected two earlier uploads
> for identity-name mismatch (`BECETTI.BECETTISECURITY` instead of
> `Ahmedbecetti.BECETTISECURITY`). Those older `.msixupload` files are still
> published under `store-package-1.0.0.0` and `store-package-1.0.0.0-pdn` for the
> record, but uploading them will fail the same validation. Use the link above.

---

## 2. Installable version (signed, side-load)

> **This is the one to download if you want to run the app.**

**[⬇ Download the signed MSIX (1.0.0.1221)](https://github.com/Ahmedbecett/BECETTI-SECURITY/releases/download/msix-test-a2cfd10/BECETTI-SECURITY_1.0.0.1221_x64.msix)**

**[🔑 Download the test certificate](https://github.com/Ahmedbecett/BECETTI-SECURITY/releases/download/msix-test-a2cfd10/BecettiTestCert.cer)**

**[📄 Install instructions](https://github.com/Ahmedbecett/BECETTI-SECURITY/releases/download/msix-test-a2cfd10/INSTALL.txt)**

### How to install (3 steps)

1. Double-click **`BecettiTestCert.cer`** → *Install Certificate* →
   **Local Machine** → *Place all certificates in the following store* →
   **Browse** → **Trusted People** → Finish.
2. Double-click **`BECETTI-SECURITY_1.0.0.1221_x64.msix`**.
3. Click **Install**.

> If you skip step 1 you will get error **`0x800B010A`** ("A certificate chain
> could not be built"). That error means the certificate was not trusted —
> nothing is wrong with the app.

This build is signed with a **self-signed test certificate**, not a
Microsoft-issued or CA-trusted one. Your PC will not trust it until you do
step 1, which is why that step exists. The Microsoft Store version will not
need it, because Microsoft signs that one itself.

---

## 3. Verification reports

**[📋 Verification report](https://github.com/Ahmedbecett/BECETTI-SECURITY/releases/download/store-package-1.0.0.0-pdn2/store-package-verification.txt)**
· **[🧪 WACK report (7.56 MB)](https://github.com/Ahmedbecett/BECETTI-SECURITY/releases/download/store-package-1.0.0.0-pdn2/WACK-REPORT.xml)**

The WACK report is the Windows App Certification Kit output: every requirement
**PASS**, `appcert.exe` exit code 0.

---

## Other links

- **[🔒 Privacy policy](https://github.com/Ahmedbecett/BECETTI-SECURITY/blob/main/store/privacy-policy.md)**
- **[📦 All releases](https://github.com/Ahmedbecett/BECETTI-SECURITY/releases)**
- **[💻 Source code](https://github.com/Ahmedbecett/BECETTI-SECURITY)**

---

### Which file am I looking at?

| You want to… | Download |
|---|---|
| **Run the app on my PC** | **#2** — the `.msix` + certificate |
| Submit to the Microsoft Store | #1 — the `.msixupload` |
| Check that the build passed certification | #3 — the WACK report |

Downloading #1 and double-clicking it will do nothing useful: Windows has no
handler for `.msixupload`. That file only means something to Partner Center.

---

*Highest-versioned sideload build is always listed on the
[releases page](https://github.com/Ahmedbecett/BECETTI-SECURITY/releases). The
version in the file name (`1.0.0.1221`) is stamped per build so that Windows
sees each download as a genuine new version and does not show "already
installed" for an older copy.*
