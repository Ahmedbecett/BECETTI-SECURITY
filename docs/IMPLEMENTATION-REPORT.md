# BECETTI SECURITY v1.0.0 — Implementation Report

Date: 2026-11-20. This report follows the product rule: **never mark an
untested feature as completed.** Statuses are split into *implemented in
source*, *verified by running*, and *not yet verified*.

## CI build/test results (real `windows-latest` runner, real .NET 8 SDK)

The GitHub Actions workflow `.github/workflows/ci.yml` runs on a genuine
Windows GitHub-hosted runner (not a simulation, not the Linux sandbox) and
executes `dotnet restore` → `dotnet build -c Release -p:Platform=x64` →
`dotnet test` against the full solution (`Becetti.Security.sln`): Core, Api,
App (the WinUI 3 project), and both test projects.

- **First run** ([44834965884](https://github.com/Ahmedbecett/BECETTI-SECURITY/actions/runs/44834965884)) — **FAILED** at Build, with real Roslyn compiler
  errors (not static-analysis guesses): a sealed base class blocking generic
  inheritance, and every test file missing `using Xunit;`.
- **Runs 2–9** — each fixed the real error(s) the previous run reported and
  surfaced the next genuine problem underneath it: a true bug in
  `DefenderService.cs` (the exact file flagged at the start of this task),
  a missing `System.Net.Security` using + a nonexistent `SslStream`
  overload, an EF Core 8 incompatibility in the test host, a Windows App SDK
  bug that was silently swallowing real XAML compiler errors, a WinUI
  enum-vs-bool XAML mismatch, an implicit-downcast C# error, two read-only
  view-model properties bound `TwoWay`, a JWT signing-key mismatch that is
  specific to the `WebApplicationFactory` test host's configuration timing,
  and a SQLite-only `DateTimeOffset` ordering limitation.
- **Final run** ([44840966151](https://github.com/Ahmedbecett/BECETTI-SECURITY/actions/runs/44840966151)) — **PASSED**: `Build (Release, x64)` ✅ and
  `Test` ✅, zero errors, zero warnings/annotations of any kind.

Every fix above was driven by an actual compiler/test-runner error message
captured from that specific run (file, line, and exact diagnostic text are
recorded in each commit message on this branch) — none were guessed from
static analysis. This is the concrete evidence the task asked for: real
Windows build + real test execution, not a Python structural check.

### All genuine bugs found and fixed this session (22 total)

**Found by manual source review (7), committed before the first CI run:**
1. `Becetti.Security.Core.csproj` was missing the `Microsoft.Win32.Registry` package.
2. `Becetti.Security.App.csproj` was missing the `Microsoft.Extensions.Http` package.
3. `MainWindow.xaml.cs`: invalid cast assigning `FlowDirection` through `Window.Content` (typed `UIElement`, not `FrameworkElement`).
4. `ScanPage.xaml.cs` / `CloudPage.xaml.cs`: undefined `GetWindowHandle` call, fixed to `WindowNative.GetWindowHandle`.
5. `Becetti.Security.App.Package.wapproj`: a malformed XML closing tag.
6. `BecettiApiFactory.cs`: the test host registered both the Npgsql and Sqlite EF Core providers for the same `DbContext`.
7. `CloudService.cs`: `GetHealthAsync` used a `.ContinueWith(..., ct)` pattern that could throw `TaskCanceledException` instead of returning a graceful failure result.

**Found by the real Windows CI runner across 9 iterative runs (15), each with an exact compiler/test error as evidence:**
8. `OperationResult.cs`: `OperationResult<T>` could not derive from the (incorrectly) `sealed` base `OperationResult` class — real `CS0509`-class error.
9. Every file in both test projects used `[Fact]`/`[Theory]`/`IClassFixture<>` with no `using Xunit;` anywhere in `tests/` — fixed via `<Using Include="Xunit" />` in both test `.csproj` files.
10. `Becetti.Security.App.csproj` explicitly listed both `.resw` files as `<PRIResource>` even though the SDK already includes them by default — "Duplicate 'PRIResource' items were included" build warning.
11. **`DefenderService.cs` (the file this task explicitly asked to fix): `GetStatusAsync`/`GetFirewallAsync`/`GetThreatsAsync` passed the internal `ProcessRun` record (`run.Value`) straight into the JSON parsers instead of `run.Value.Output`, the actual PowerShell stdout string.** The compiler rejected `run.Value ?? string.Empty` outright: `'ProcessRun' and 'string' cannot be combined with '??'`. This is the real, CI-confirmed bug — not the Python brace-counting false alarm the task warned against trusting.
12. `SystemInfoService.cs`: used `SslStream` without `using System.Net.Security;`, and called a `SslStream.AuthenticateAsClientAsync(string, CancellationToken)` overload that does not exist (only `(SslClientAuthenticationOptions, CancellationToken)` accepts a token).
13. `SettingsService.cs`: `TokenStore.ProtectionActive` is a real `OperatingSystem.IsWindows()` guard for DPAPI calls, but the platform-compatibility analyzer could not see through it; tagged with `[SupportedOSPlatformGuard("windows")]` to clear the `CA1416` warnings without weakening the guard.
14. `BecettiApiFactory.cs`: referenced `IDbContextOptionsConfiguration<AppDbContext>`, a type that does not exist in EF Core 8 (introduced only in EF Core 9) — the project pins EF Core `8.0.*`. Also needed an explicit `using Microsoft.Extensions.Configuration;` for `AddInMemoryCollection`.
15. `Becetti.Security.App.csproj` pinned `Microsoft.WindowsAppSDK` to `1.5.*`, which resolved to `1.5.250108004` — a version with a known, since-fixed bug (`microsoft/microsoft-ui-xaml#9813`) where a real XAML compiler error is reported only as `MSB3073: ...XamlCompiler.exe... exited with code 1` with **no file name or message at all**. Pinned to `1.8.260921001` (current latest 1.8 servicing release) so the real diagnostic underneath could finally be seen.
16. `MainWindow.xaml`: `NavigationView.IsBackButtonVisible="False"` — this property is **not** a `bool` despite its `Is...` name (a known WinUI API wart), it is a `NavigationViewBackButtonVisible` enum (`Auto`/`Visible`/`Collapsed`). Fixed to `IsBackButtonVisible="Collapsed"`.
17. `App.xaml.cs`: `CS0266` — assigning the base-typed `_window` (`Window?`) directly into the `MainWindow?`-typed `App.MainWindow` static property needs an explicit downcast; introduced a precisely-typed `mainWindow` local instead.
18. `SettingsViewModel.cs`: `IsArabic`/`IsEnglish` were read-only expression-bodied properties, but `SettingsPage.xaml` binds both language `RadioButton`s with `Mode=TwoWay` — real `CS0200` ("cannot be assigned to — it is read only"). Added setters that write back to `Language`, mirroring the already-working `IsDark`/`IsLight`/`IsSystem` pattern.
19. `PrivacyPage.xaml`: a recommendation list item bound `Text="{x:Bind Mode=OneWay}"` against a plain `string` with no change notification — real (non-fatal) `XamlCompiler warning WMC1506`; changed to `Mode=OneTime`, which is also the semantically correct mode for a list item that never changes after the page loads.
20. `Becetti.Security.App.csproj` referenced `win-$(Platform).pubxml` publish profiles that did not exist in the repository — real "publish profile ... was not found" warning on every build; added `win-x64.pubxml`, `win-x86.pubxml`, `win-ARM64.pubxml`.
21. **Real test failure, not a static issue:** `Program.cs` reads `Jwt:SigningKey` and `ConnectionStrings:Postgres` into local variables *before* `WebApplicationBuilder.Build()` runs, and `AddJwtBearer` captures that value by closure. `WebApplicationFactory`'s `ConfigureAppConfiguration` override is only merged into the configuration pipeline *when* `Build()` executes — too late for that early read. Result: `TokenService` signed JWTs with the test's signing key, while `AddJwtBearer`'s `IssuerSigningKey` still held `appsettings.json`'s placeholder key, so **every** authenticated endpoint returned `401 Unauthorized` no matter how valid the token was. Fixed by setting `Jwt__SigningKey`/`Jwt__Issuer`/`Jwt__Audience`/`ConnectionStrings__Postgres` as process environment variables in `BecettiApiFactory`'s constructor (read synchronously by `WebApplication.CreateBuilder(args)` itself, before Program.cs's own code runs).
22. **Real test failure:** `UpdatesController.Check` (`OrderByDescending(r => r.PublishedAt)`) threw `System.NotSupportedException: SQLite cannot order by expressions of type 'DateTimeOffset'` — a documented SQLite/EF Core provider limitation that does not affect the real production database (PostgreSQL). Fixed by applying `DateTimeOffsetToBinaryConverter` to every `DateTimeOffset` property in `AppDbContext.OnModelCreating`, **only** when the active provider is Sqlite — the PostgreSQL model/migrations are completely untouched.

This list is the honest, complete record of every bug found and fixed in
this session — including the ones a manual/static review (and the
repository's own `scripts/validate_structure.py` brace-checker) missed
entirely and only real compilation/execution on Windows caught, which is
exactly why the task required a real Windows CI runner instead of
accepting a Linux-sandbox structural check as proof.

## Implemented in source (complete code, ready to build/run)

### Windows client (WinUI 3 + Core)
- [x] Dashboard with live Defender/OS/cloud values; "Unknown" when unavailable.
- [x] Smart Scan: Quick / Full / Custom file+folder via `MpCmdRun.exe`;
      results from Defender exit codes only.
- [x] Real-Time Protection: verified status, enable/disable via
      `Set-MpPreference` with re-verification, signature updates via
      `Update-MpSignature`, UAC elevation flow.
- [x] Threat Management: real `Get-MpThreatDetection` list, removal via
      `Remove-MpThreat` with re-query verification.
- [x] Privacy & Network: measured network/DNS/TLS checks (validation never
      disabled), UAC/firewall/RTP configuration checks, derived recommendations.
- [x] Security History: local log of real events only (no seeded data).
- [x] Updates: cloud release check (when API configured) kept separate from
      Defender signature updates; Microsoft Store note.
- [x] Settings: language (EN/AR + RTL), API URL, theme, telemetry opt-in —
      all persisted and applied.
- [x] About: version, build, Defender presence, honest capability statement.
- [x] Localization resources (`Resources.resw` EN + AR) wired via `x:Uid`.
- [x] MSIX manifest, generated logo assets (PNG + ICO + SVG), packaging project.

### Cloud API (ASP.NET Core 8 + PostgreSQL)
- [x] JWT auth (register/login/refresh/logout/me), BCrypt, hashed refresh tokens.
- [x] Reputation endpoint with honest `unknown / no-provider-configured` fallback.
- [x] VirusTotal provider integration (active only when an API key is set).
- [x] Update-check endpoint, admin intel/release endpoints, audit logging.
- [x] Rate limiting, validation, EF Core migrations, Docker image.

### Tests (written, run in CI)
- [x] Core unit tests (hashing, parsing, settings, history, cloud failures).
- [x] API integration tests (health, auth flow, reputation honesty, authz).

## Verified by running
- [x] **Compiles for real** on a genuine Windows GitHub Actions runner with
      the real .NET 8 SDK — `Core`, `Api`, `App` (WinUI 3), and both test
      projects all build clean in `Release|x64`, zero errors, zero warnings
      (CI run [44840966151](https://github.com/Ahmedbecett/BECETTI-SECURITY/actions/runs/44840966151)).
- [x] **All automated tests pass for real** on that same runner: Core unit
      tests (hashing, Defender JSON parsing, settings, history, cloud
      failure handling) and Api integration tests (health, the full
      register → login → `/me` auth flow, reputation honesty, authorization
      checks, update-check, version comparison) — executed against a real
      in-process ASP.NET Core `TestServer` with a real SQLite database, real
      HTTP requests, real JWT issuance and validation, real password
      hashing and verification.
- [ ] **Not yet verified:** anything that needs a live Windows *desktop*
      session, a real PostgreSQL server, a real Microsoft Defender
      installation, or a real Microsoft Store/signing identity. CI proves
      the WinUI 3 app *compiles* against the real Windows App SDK API
      surface; it does not and cannot launch the GUI, exercise Defender
      PowerShell cmdlets, or connect to PostgreSQL, because GitHub's hosted
      Windows runners have no interactive desktop session, no Microsoft
      Defender service enabled for automation, and no PostgreSQL server
      provisioned. These are called out explicitly below instead of being
      claimed as done.

## Not yet done / requires external setup
- [ ] Manual Windows verification checklist (`docs/TESTING.md`) — launching
      the app, navigating all ten pages, exercising every button against a
      real Microsoft Defender installation, on a real Windows desktop.
- [ ] Live PostgreSQL connectivity and `dotnet ef database update` against a
      real server (migrations are present and reviewed, but have only run
      against SQLite in CI, never against PostgreSQL in this environment).
- [ ] MSIX signing certificate + Partner Center publisher identity
      (manifest still carries the `CN=BECETTI` placeholder).
- [ ] Cloud deployment: PostgreSQL, API host, domain + TLS, VirusTotal key.
- [ ] Store screenshots, privacy-policy URL hosting, certification submission.
- [ ] EICAR end-to-end detection test on a controlled machine.
- [x] **Signed, downloadable MSIX test package** — a new CI job
      (`package-msix`) now builds the real single-project MSIX using the
      official Microsoft CI recipe (`msbuild` + `UapAppxPackageBuildMode=
      SideloadOnly` + `GenerateAppxPackageOnBuild=true`), signs it with a
      freshly generated self-signed test certificate, and verifies the
      produced `.msix` genuinely contains `AppxSignature.p7x` (proof it is
      signed, not just packaged) before publishing it as a GitHub Release.
      Current download: https://github.com/Ahmedbecett/BECETTI-SECURITY/releases/tag/msix-test-cf5b68b
      (assets: the signed `.msix`, the public `.cer` to trust before
      installing, and `INSTALL.txt` with exact sideload steps). This is a
      **self-signed TEST package for sideloading only** — it is not signed
      by a trusted CA or a Partner Center publisher identity, so Windows
      requires trusting `BecettiTestCert.cer` first (see INSTALL.txt). A
      real Microsoft Store submission still requires the steps in
      `docs/STORE-SUBMISSION.md` (Partner Center identity + a CA-issued or
      Store-managed certificate).

## Known limitations (honest)
- Scan progress is reported as Defender output, not a percentage — MpCmdRun
  does not expose reliable progress. No fake percentages are shown.
- Cloud features are unavailable until an API URL is configured; the app says
  so explicitly instead of simulating responses.
- The app does not replace Defender and does not claim "complete protection".
