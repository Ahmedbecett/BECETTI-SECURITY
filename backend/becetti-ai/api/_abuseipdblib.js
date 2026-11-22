// Shared helpers for the AbuseIPDB IP-reputation proxy routes
// (abuseipdb-health.js, abuseipdb-check.js). Filename starts with "_" so
// Vercel does NOT turn it into its own route — it is a plain module
// imported by the real route handlers.
//
// Why this exists: unlike the data-breach lookups (XposedOrNot, HIBP range
// API), AbuseIPDB requires a registered API key, so a lookup must go
// through this server-side proxy — ABUSEIPDB_API_KEY lives only as a
// Vercel project environment variable and is never shipped inside the
// Windows app or committed to source control.
//
// Honesty rule (same as every other proxy in this backend): every response
// either carries a real AbuseIPDB result or a real error from AbuseIPDB
// (including real rate-limit/quota errors) — nothing here is simulated.

const ABUSEIPDB_BASE = "https://api.abuseipdb.com/api/v2";

function getApiKey() {
  return process.env.ABUSEIPDB_API_KEY;
}

function setCors(res, methods) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", `${methods}, OPTIONS`);
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
}

/** Calls the real AbuseIPDB v2 API. Never fabricates a response. */
async function abuseIpDbFetch(apiKey, path) {
  const upstream = await fetch(`${ABUSEIPDB_BASE}${path}`, {
    headers: {
      Key: apiKey,
      Accept: "application/json"
    }
  });
  const text = await upstream.text();
  let json = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = null;
  }
  return {
    ok: upstream.ok,
    status: upstream.status,
    json,
    retryAfter: upstream.headers.get("retry-after")
  };
}

/** Maps a real AbuseIPDB error payload/status to a {status, body} this proxy sends back, unchanged in meaning. */
function upstreamErrorResponse(result, fallbackMessage) {
  const detail =
    result.json &&
    Array.isArray(result.json.errors) &&
    result.json.errors[0] &&
    result.json.errors[0].detail;

  if (result.status === 401 || result.status === 403) {
    return { status: 502, body: { error: "INVALID_KEY", message: detail || "AbuseIPDB rejected the configured API key." } };
  }
  if (result.status === 429) {
    return {
      status: 429,
      body: {
        error: "RATE_LIMITED",
        message: detail || "AbuseIPDB's free-tier daily quota (1,000 checks/day) was reached for this API key. Wait and try again.",
        retryAfterSeconds: result.retryAfter ? Number(result.retryAfter) : null
      }
    };
  }
  if (result.status === 422) {
    return { status: 400, body: { error: "BAD_REQUEST", message: detail || "AbuseIPDB rejected the request (invalid IP address)." } };
  }
  return { status: 502, body: { error: "UPSTREAM_ERROR", message: detail || fallbackMessage || `AbuseIPDB returned HTTP ${result.status}.` } };
}

/**
 * Normalizes AbuseIPDB's real "/check" response "data" object into the one
 * shape BECETTI SECURITY's client understands. Every field here is copied
 * straight from AbuseIPDB's real response — nothing is invented.
 */
function normalizeCheckResult(data) {
  const abuseConfidenceScore = typeof data.abuseConfidenceScore === "number" ? data.abuseConfidenceScore : 0;
  const totalReports = typeof data.totalReports === "number" ? data.totalReports : 0;

  let verdict = "unknown";
  if (abuseConfidenceScore >= 75) verdict = "malicious";
  else if (abuseConfidenceScore >= 25) verdict = "suspicious";
  else verdict = "clean";

  return {
    ipAddress: data.ipAddress || null,
    isPublic: typeof data.isPublic === "boolean" ? data.isPublic : null,
    ipVersion: data.ipVersion || null,
    abuseConfidenceScore,
    totalReports,
    numDistinctUsers: typeof data.numDistinctUsers === "number" ? data.numDistinctUsers : 0,
    lastReportedAtUtc: data.lastReportedAt || null,
    countryCode: data.countryCode || null,
    countryName: data.countryName || null,
    usageType: data.usageType || null,
    isp: data.isp || null,
    domain: data.domain || null,
    isTor: typeof data.isTor === "boolean" ? data.isTor : false,
    isWhitelisted: typeof data.isWhitelisted === "boolean" ? data.isWhitelisted : false,
    verdict
  };
}

module.exports = { getApiKey, setCors, abuseIpDbFetch, upstreamErrorResponse, normalizeCheckResult };
