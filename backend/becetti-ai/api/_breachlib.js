// Shared helpers for the data-breach monitoring proxy routes (breach-health.js,
// breach-email.js, breach-password.js). Filename starts with "_" so Vercel
// does NOT turn it into its own route — it is a plain module imported by the
// real route handlers.
//
// Why this exists: BECETTI SECURITY's core protection stays Microsoft
// Defender plus the app's own local checks. Breach monitoring is an
// optional, clearly-labelled extra: "has this email or password shown up in
// a known public data breach?" — exactly the same spirit as the VirusTotal
// second opinion, just for leaked-credential exposure instead of malware.
//
// Both upstream services used here are free and require no API key:
//   - XposedOrNot (https://xposedornot.com) for email breach lookups.
//   - HIBP's "Pwned Passwords" k-anonymity range API
//     (https://api.pwnedpasswords.com) for password exposure checks.
// There is no secret to protect in either case, so this proxy exists purely
// so the desktop app never makes a direct third-party network call and every
// look-up goes through one auditable, rate-limit-aware path, matching the
// architecture already used for VirusTotal.
//
// Honesty rule (same as chat.js / _vtlib.js): every response either carries
// a real upstream result or a real upstream error — nothing here is
// simulated, guessed, or fabricated.
//
// Privacy: the password-check endpoint only ever receives a 5-character
// SHA-1 prefix from the client (the client hashes the password locally and
// truncates it before sending anything). This proxy never sees, logs, or
// stores a full password hash, let alone a plaintext password.

const XON_BASE = "https://api.xposedornot.com/v1";
const HIBP_RANGE_BASE = "https://api.pwnedpasswords.com/range";

function setCors(res, methods) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", `${methods}, OPTIONS`);
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
}

async function fetchJson(url, options = {}) {
  const upstream = await fetch(url, options);
  const text = await upstream.text();
  let json = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = null;
  }
  return { ok: upstream.ok, status: upstream.status, json, text };
}

async function fetchText(url, options = {}) {
  const upstream = await fetch(url, options);
  const text = await upstream.text();
  return { ok: upstream.ok, status: upstream.status, text };
}

/**
 * Normalizes XposedOrNot's real /v1/breach-analytics response into the one
 * shape BECETTI SECURITY's client understands. Every field is copied
 * straight from the upstream response — nothing here is invented. A
 * BreachMetrics/ExposedBreaches pair of null (XposedOrNot's own
 * documented "not found" shape) means genuinely no known breach, not a
 * failed lookup.
 */
function normalizeEmailBreachAnalytics(email, json) {
  const metrics = json && json.BreachMetrics;
  const exposed = json && json.ExposedBreaches && json.ExposedBreaches.breaches_details;

  if (!metrics || !Array.isArray(exposed) || exposed.length === 0) {
    return {
      status: "completed",
      email,
      breached: false,
      breachCount: 0,
      breaches: [],
      riskLabel: null,
      riskScore: null,
      message: "No known public data breach contains this email address."
    };
  }

  const breaches = exposed.map((b) => ({
    name: b.breach || "Unknown",
    domain: b.domain || null,
    industry: b.industry || null,
    description: b.details || null,
    exposedData: typeof b.xposed_data === "string" ? b.xposed_data.split(";").filter(Boolean) : [],
    breachDate: b.xposed_date || null,
    recordsExposed: typeof b.xposed_records === "number" ? b.xposed_records : null,
    passwordRisk: b.password_risk || null,
    verified: b.verified === "Yes" || b.verified === true,
    referenceUrl: b.references || null
  }));
  breaches.sort((a, b) => a.name.localeCompare(b.name));

  const riskEntry = metrics.risk && metrics.risk[0];

  return {
    status: "completed",
    email,
    breached: true,
    breachCount: breaches.length,
    breaches,
    riskLabel: riskEntry ? riskEntry.risk_label : null,
    riskScore: riskEntry && typeof riskEntry.risk_score === "number" ? riskEntry.risk_score : null,
    message: `Found in ${breaches.length} known data breach${breaches.length === 1 ? "" : "es"}.`
  };
}

module.exports = {
  XON_BASE,
  HIBP_RANGE_BASE,
  setCors,
  fetchJson,
  fetchText,
  normalizeEmailBreachAnalytics
};
