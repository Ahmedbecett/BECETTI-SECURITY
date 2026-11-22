// Shared helpers for the VirusTotal proxy routes (vt-health.js, vt-url.js,
// vt-file.js, vt-analysis.js). Filename starts with "_" so Vercel does NOT
// turn it into its own route — it is a plain module imported by the real
// route handlers.
//
// Why this exists: BECETTI SECURITY's core protection engine is, and stays,
// Microsoft Defender (read/managed through its own official interfaces).
// VirusTotal is an optional, clearly-labelled SECOND OPINION from ~70
// third-party antivirus engines, reached only through this server-side
// proxy so the VirusTotal API key is never shipped inside the Windows app
// or committed to source control (VIRUSTOTAL_API_KEY lives only as a
// Vercel project environment variable).
//
// Honesty rules enforced here (same principle as chat.js): every response
// either carries a real VirusTotal result or a real error from VirusTotal
// (including real rate-limit/quota errors) — nothing here is simulated.

const VT_BASE = "https://www.virustotal.com/api/v3";

function getApiKey() {
  return process.env.VIRUSTOTAL_API_KEY;
}

function setCors(res, methods) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", `${methods}, OPTIONS`);
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
}

/** Calls the real VirusTotal v3 API. Never fabricates a response. */
async function vtFetch(apiKey, path, options = {}) {
  const upstream = await fetch(`${VT_BASE}${path}`, {
    ...options,
    headers: {
      ...(options.headers || {}),
      "x-apikey": apiKey
    }
  });
  const text = await upstream.text();
  let json = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = null;
  }
  return { ok: upstream.ok, status: upstream.status, json, retryAfter: upstream.headers.get("retry-after") };
}

/** Maps a real VirusTotal error payload/status to a {status, body} this proxy sends back, unchanged in meaning. */
function upstreamErrorResponse(result, fallbackMessage) {
  const vtMessage = result.json && result.json.error && result.json.error.message;
  if (result.status === 401 || result.status === 403) {
    return { status: 502, body: { error: "INVALID_KEY", message: vtMessage || "VirusTotal rejected the configured API key." } };
  }
  if (result.status === 429) {
    return {
      status: 429,
      body: {
        error: "RATE_LIMITED",
        message: vtMessage || "VirusTotal's request-rate or daily quota limit was reached for this API key. Wait and try again.",
        retryAfterSeconds: result.retryAfter ? Number(result.retryAfter) : null
      }
    };
  }
  if (result.status === 404) {
    return { status: 404, body: { error: "NOT_FOUND", message: vtMessage || "VirusTotal has no existing report for this item." } };
  }
  return { status: 502, body: { error: "UPSTREAM_ERROR", message: vtMessage || fallbackMessage || `VirusTotal returned HTTP ${result.status}.` } };
}

/**
 * Normalizes a VirusTotal "attributes" object (from either a file/URL report
 * or an analysis) into the one shape BECETTI SECURITY's client understands.
 * Every field here is copied straight from VirusTotal's real response —
 * nothing is invented, and an engine only appears in `engines` if VirusTotal
 * itself flagged it malicious or suspicious.
 */
function normalizeAttributes(attributes, kind, meta, idForPermalink) {
  const stats = attributes.last_analysis_stats || attributes.stats || null;
  const results = attributes.last_analysis_results || attributes.results || null;

  const engines = [];
  if (results && typeof results === "object") {
    for (const [engineName, verdict] of Object.entries(results)) {
      if (verdict && (verdict.category === "malicious" || verdict.category === "suspicious")) {
        engines.push({
          name: verdict.engine_name || engineName,
          category: verdict.category,
          result: verdict.result || null
        });
      }
    }
    engines.sort((a, b) => a.name.localeCompare(b.name));
  }

  const malicious = stats ? stats.malicious || 0 : 0;
  const suspicious = stats ? stats.suspicious || 0 : 0;
  const harmless = stats ? stats.harmless || 0 : 0;
  const undetected = stats ? stats.undetected || 0 : 0;
  const timeout = stats ? stats.timeout || 0 : 0;
  const total = malicious + suspicious + harmless + undetected + timeout;

  const sha256 = (meta && meta.file_info && meta.file_info.sha256) || attributes.sha256 || null;
  const url = (meta && meta.url_info && meta.url_info.url) || attributes.url || null;
  const urlPermalinkId = (meta && meta.url_info && meta.url_info.id) || null;

  const dateEpoch = attributes.last_analysis_date || attributes.date || null;

  let permalink = null;
  if (kind === "file" && sha256) permalink = `https://www.virustotal.com/gui/file/${sha256}`;
  else if (kind === "url" && urlPermalinkId) permalink = `https://www.virustotal.com/gui/url/${urlPermalinkId}`;
  else if (idForPermalink) permalink = `https://www.virustotal.com/gui/search/${encodeURIComponent(idForPermalink)}`;

  return {
    kind,
    stats: { malicious, suspicious, harmless, undetected, timeout, total },
    detectionRatio: `${malicious + suspicious}/${total}`,
    verdict: malicious > 0 ? "malicious" : suspicious > 0 ? "suspicious" : total > 0 ? "clean" : "unknown",
    engines,
    sha256,
    url,
    scanDateUtc: dateEpoch ? new Date(dateEpoch * 1000).toISOString() : null,
    permalink
  };
}

module.exports = { getApiKey, setCors, vtFetch, upstreamErrorResponse, normalizeAttributes };
