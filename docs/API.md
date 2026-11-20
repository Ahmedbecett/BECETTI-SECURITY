# BECETTI SECURITY Cloud API — Reference

Base URL is configured in the app (Settings → Cloud API URL). All endpoints
are HTTPS. Errors return JSON with an `error` field and a proper HTTP status.

## Health
`GET /health` — no auth. Returns `{ status, version, serverTime }`.

## Auth (`/api/v1/auth`, rate limit 10/min/IP)
| Endpoint | Method | Auth | Description |
|---|---|---|---|
| `/register` | POST | — | Create account `{email, password}` → tokens |
| `/login` | POST | — | Sign in → tokens |
| `/refresh` | POST | — | Rotate refresh token → new tokens |
| `/logout` | POST | Bearer | Revoke refresh token |
| `/me` | GET | Bearer | Current account `{email, isAdmin}` |

Passwords: minimum 10 characters, stored as BCrypt hashes. Refresh tokens are
stored hashed server-side.

## Reputation (`/api/v1/reputation`, Bearer, 120/min/IP)
`POST /check` `{ sha256 }` → `{ sha256, verdict, source, detail, checkedAt }`.
- `verdict`: `clean | malicious | suspicious | unknown`
- `source`: `becetti-db | virustotal | no-provider-configured`
- Results are cached 24h in PostgreSQL. When no provider is configured the
  server honestly returns `unknown / no-provider-configured`.

## Updates (`/api/v1/updates`, Bearer)
`GET /check?currentVersion=1.0.0&channel=stable` →
`{ currentVersion, latestVersion, updateAvailable, channel, releaseNotes, storeUrl }`.

## Admin (`/api/v1/admin`, Bearer + Admin role)
- `GET /intel/stats` — real counts from the database.
- `POST /reputation/ingest` — manually record a verdict (audited).
- `GET /releases`, `POST /releases` — list / publish application releases.

## Deployment configuration (environment variables)
| Variable | Purpose |
|---|---|
| `ConnectionStrings__Postgres` | PostgreSQL connection string |
| `Jwt__SigningKey` | JWT signing key (≥32 chars) |
| `VirusTotal__ApiKey` | VirusTotal API key (optional) |
| `AdminSeed__Email` / `AdminSeed__Password` | First admin account (optional) |

TLS must be terminated at a reverse proxy (Caddy/nginx) in front of the
container; the app trusts forwarded headers. See `src/Becetti.Security.Api/Dockerfile`.
