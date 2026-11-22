# BECETTI AI backend

Minimal Vercel serverless API that lets the BECETTI SECURITY Windows app talk
to an AI model (Google Gemini) without ever embedding an API key inside the
Windows app itself — per the app's own security rules (API keys live on the
server, never inside the client).

## Why this exists

The BECETTI SECURITY WinUI app calls this backend over HTTPS instead of
calling Gemini directly. That keeps `GEMINI_API_KEY` out of the shipped
`.msix` package entirely: it is only ever set as a Vercel project
environment variable (`GEMINI_API_KEY`, type `sensitive`), configured through
the Vercel dashboard/API, never committed here.

## Endpoints

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

## Deployment

Deployed as a standalone Vercel project (not tied to any other app in this
account). No build step and no npm dependencies — both functions use only
Node's built-in `fetch`. Redeploy by pushing new file contents for
`api/chat.js` / `api/health.js` through the Vercel API/dashboard.

## Security notes

- This backend never stores chat content.
- It only accepts `POST` for `/api/chat` and only forwards `role`/`content`
  fields, after trimming message count and length, to limit abuse.
- CORS is open (`*`) because the caller is a desktop app (WinUI `HttpClient`),
  not a browser page that needs to be restricted to an origin.
