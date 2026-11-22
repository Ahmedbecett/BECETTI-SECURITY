# BECETTI backend

Minimal Vercel serverless API that lets the BECETTI SECURITY Windows app talk
to external cloud services (Google Gemini for BECETTI AI, VirusTotal for
threat intelligence) without ever embedding an API key inside the Windows
app itself — per the app's own security rules (API keys live on the server,
never inside the client, never committed to source control).

## Why this exists

The BECETTI SECURITY WinUI app calls this backend over HTTPS instead of
calling Gemini or VirusTotal directly. That keeps `GEMINI_API_KEY` and
`VIRUSTOTAL_API_KEY` out of the shipped `.msix` package entirely: both are
only ever set as Vercel project environment variables (type `sensitive`),
configured through the Vercel dashboard/API, never committed here.

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
- CORS is open (`*`) because the caller is a desktop app (WinUI `HttpClient`),
  not a browser page that needs to be restricted to an origin.
