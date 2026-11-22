# BECETTI backend

Minimal Vercel serverless API that lets the BECETTI SECURITY Windows app talk
to external cloud services (Google Gemini for BECETTI AI, VirusTotal for
threat intelligence, XposedOrNot + HIBP for data-breach monitoring) without
ever embedding an API key inside the Windows app itself — per the app's own
security rules (API keys live on the server, never inside the client, never
committed to source control).

## Why this exists

The BECETTI SECURITY WinUI app calls this backend over HTTPS instead of
calling these services directly. That keeps `GEMINI_API_KEY` and
`VIRUSTOTAL_API_KEY` out of the shipped `.msix` package entirely: both are
only ever set as Vercel project environment variables (type `sensitive`),
configured through the Vercel dashboard/API, never committed here. The
data-breach routes use two upstream services that are free and require no
key at all (XposedOrNot and HIBP's Pwned Passwords range API) — they are
still proxied through this backend for the same auditable, single-path
architecture, not because they hold a secret.

## Endpoints

### BECETTI AI (Gemini)

- `POST /api/chat` — body `{ "messages": [{ "role": "user", "content": "..." }] }`.
  Proxies to Google's Gemini `generateContent` API (model `gemini-2.5-flash`)
  with BECETTI AI's system prompt (the honesty/safety rules from the product
  spec) sent as `system_instruction`. Returns
  `{ "reply": "...", "model": "...", "usage": {...} }` on success, or
  `{ "error": "CODE", "message": "..." }` on any real failure — it never
  fabricates a reply.
- `GET /api/health` — makes one real call to Gemini (`GET /v1beta/models`) to
  report whether the configured key is actually valid and Gemini is
  reachable. Used for diagnostics only; never used to fake a "healthy"
  status.

### Threat Intelligence (VirusTotal)

All VirusTotal routes require `VIRUSTOTAL_API_KEY` to be set. Core logic
lives in `api/_vtlib.js` (filename starts with `_` so Vercel does not expose
it as its own route — it is a shared module only).

- `GET /api/vt-health` — one real, cheap VirusTotal lookup to confirm the
  configured key is accepted and VirusTotal is reachable.
- `POST /api/vt-file` — body `{ "sha256": "..." }` and/or
  `{ "fileBase64": "...", "fileName": "..." }`. Always tries a hash-only
  lookup first (the file is never uploaded just to check a known hash); only
  uploads the actual file content to VirusTotal for a fresh scan when the
  hash is unknown AND the caller explicitly also sent `fileBase64`. Capped
  at 3 MB of raw file content per request (reported honestly as
  `FILE_TOO_LARGE` beyond that, never silently truncated).
- `POST /api/vt-url` — body `{ "url": "..." }`. Submits a URL to VirusTotal
  for analysis by its ~70 partner engines; returns the real analysis id.
- `GET /api/vt-analysis?id=...` — polls a real VirusTotal analysis (file or
  URL) by id and returns either the current in-progress status or the full
  normalized completed report (detection ratio, per-engine verdicts,
  scan date, GUI permalink).

Every one of these returns VirusTotal's own real error (including real
429 rate-limit/quota errors, forwarded with `Retry-After` when present) on
failure — nothing here is simulated, cached as fake data, or backfilled.

### Data Breach Monitoring (XposedOrNot + HIBP)

Neither upstream here needs an API key — both are free, public, keyless
services. Shared logic lives in `api/_breachlib.js`.

- `GET /api/breach-health` — one real, cheap read against each upstream
  (a domain-filtered breach-catalog lookup for XposedOrNot, and the
  well-known public `5BAA6` prefix for HIBP's range API) to confirm both are
  reachable.
- `GET /api/breach-email?email=...` — proxies XposedOrNot's real
  `breach-analytics` endpoint and returns a normalized report: whether the
  address appears in any known public breach, and if so the list of
  breaches (name, domain, industry, date, records exposed, exposed data
  categories, password-crackability rating) plus an overall risk
  label/score. A "not breached" result only ever comes from XposedOrNot's
  own documented empty shape — never guessed.
- `GET /api/breach-password?prefix=XXXXX` — proxies HIBP's "Pwned
  Passwords" k-anonymity range API. The client computes a SHA-1 hash of the
  password **locally** and sends only its first 5 hex characters as
  `prefix`; this endpoint forwards just that prefix to HIBP and returns the
  full list of matching suffix:count pairs for the client to match locally.
  Neither this proxy nor HIBP ever receives the full hash or the password
  itself — the architecture guarantees that, it is not just a policy.

## Deployment

Deployed as a standalone Vercel project (not tied to any other app in this
account). No build step and no npm dependencies — all functions use only
Node's built-in `fetch`/`FormData`/`Blob`. Redeploy by pushing new file
contents through the Vercel API/dashboard, or via a new deployment from the
linked GitHub repository.

## Security notes

- This backend never stores chat content or scanned file/URL content.
- `/api/chat` only accepts `POST` and only forwards `role`/`content` fields,
  after trimming message count and length, to limit abuse.
- `/api/vt-file` enforces a hard 3 MB upload cap and only uploads a file when
  the caller has explicitly opted in by sending its content — a hash-only
  check never leaves the device content off the wire beyond the hash itself.
- Uploading an unknown file to VirusTotal shares that file with VirusTotal
  and its security-industry partners, per VirusTotal's own Terms of Service.
  The Windows app is responsible for showing the user a clear warning before
  taking that step; this proxy does not make that decision on the user's
  behalf.
- `/api/breach-password` never sees a full password hash, let alone a
  plaintext password — only a 5-character SHA-1 prefix, by design (the same
  k-anonymity model HIBP itself designed and recommends).
- `/api/breach-email` does not store the email addresses it is asked about;
  each request is a stateless pass-through to XposedOrNot.
- CORS is open (`*`) because the caller is a desktop app (WinUI `HttpClient`),
  not a browser page that needs to be restricted to an origin.
