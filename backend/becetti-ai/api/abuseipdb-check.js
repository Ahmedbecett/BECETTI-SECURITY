// BECETTI SECURITY — IP reputation proxy (AbuseIPDB).
//
// An optional, clearly-labelled SECOND OPINION on a single IP address the
// user chooses to check — e.g. a Network Monitor connection that looks
// unfamiliar. Reached only through this server-side proxy so the
// AbuseIPDB API key is never shipped inside the Windows app or committed
// to source control (ABUSEIPDB_API_KEY lives only as a Vercel project
// environment variable).
const { getApiKey, setCors, abuseIpDbFetch, upstreamErrorResponse, normalizeCheckResult } = require("./_abuseipdblib");

// Conservative IPv4/IPv6 shape check — the real validation is AbuseIPDB's own (HTTP 422
// on a genuinely malformed address); this just rejects obviously-wrong input early.
const IP_RE = /^[0-9a-fA-F:.]{2,45}$/;

module.exports = async (req, res) => {
  setCors(res, "GET");
  if (req.method === "OPTIONS") {
    res.status(204).end();
    return;
  }
  if (req.method !== "GET") {
    res.status(405).json({ error: "METHOD_NOT_ALLOWED", message: "Use GET." });
    return;
  }

  const apiKey = getApiKey();
  if (!apiKey) {
    res.status(503).json({
      error: "NOT_CONFIGURED",
      message: "IP reputation lookups are not configured on the server yet. The administrator needs to set ABUSEIPDB_API_KEY."
    });
    return;
  }

  const ipAddress = typeof req.query.ip === "string" ? req.query.ip.trim() : "";
  if (!ipAddress || ipAddress.length > 45 || !IP_RE.test(ipAddress)) {
    res.status(400).json({ error: "BAD_REQUEST", message: "Query parameter 'ip' must be a valid IPv4 or IPv6 address." });
    return;
  }

  const maxAgeInDaysRaw = typeof req.query.maxAgeInDays === "string" ? parseInt(req.query.maxAgeInDays, 10) : 90;
  const maxAgeInDays = Number.isFinite(maxAgeInDaysRaw) && maxAgeInDaysRaw > 0 && maxAgeInDaysRaw <= 365 ? maxAgeInDaysRaw : 90;

  try {
    const result = await abuseIpDbFetch(apiKey, `/check?ipAddress=${encodeURIComponent(ipAddress)}&maxAgeInDays=${maxAgeInDays}`);

    if (!result.ok || !result.json || !result.json.data) {
      const mapped = upstreamErrorResponse(result, "AbuseIPDB lookup failed.");
      res.status(mapped.status).json(mapped.body);
      return;
    }

    const normalized = normalizeCheckResult(result.json.data);
    res.status(200).json({ status: "completed", ...normalized });
  } catch (err) {
    res.status(502).json({ error: "NETWORK_ERROR", message: String((err && err.message) || err) });
  }
};
