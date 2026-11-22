// BECETTI SECURITY — VirusTotal URL-reputation proxy. Submits a URL to
// VirusTotal for analysis by ~70 real third-party engines and returns the
// real analysis id to poll via /api/vt-analysis. Never fabricates a verdict.
const { getApiKey, setCors, vtFetch, upstreamErrorResponse } = require("./_vtlib");

module.exports = async (req, res) => {
  setCors(res, "POST");
  if (req.method === "OPTIONS") {
    res.status(204).end();
    return;
  }
  if (req.method !== "POST") {
    res.status(405).json({ error: "METHOD_NOT_ALLOWED", message: "Use POST." });
    return;
  }

  const apiKey = getApiKey();
  if (!apiKey) {
    res.status(503).json({
      error: "NOT_CONFIGURED",
      message: "VirusTotal integration is not configured on the server yet. The administrator needs to set VIRUSTOTAL_API_KEY."
    });
    return;
  }

  let body = req.body;
  if (typeof body === "string") {
    try {
      body = JSON.parse(body);
    } catch {
      body = {};
    }
  }
  body = body || {};

  const url = typeof body.url === "string" ? body.url.trim() : "";
  if (!url || !/^https?:\/\//i.test(url)) {
    res.status(400).json({ error: "BAD_REQUEST", message: "A valid http:// or https:// url is required." });
    return;
  }
  if (url.length > 2048) {
    res.status(400).json({ error: "BAD_REQUEST", message: "url is too long." });
    return;
  }

  try {
    const submit = await vtFetch(apiKey, "/urls", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: `url=${encodeURIComponent(url)}`
    });

    if (!submit.ok || !submit.json || !submit.json.data) {
      const mapped = upstreamErrorResponse(submit, "VirusTotal URL submission failed.");
      res.status(mapped.status).json(mapped.body);
      return;
    }

    res.status(202).json({
      status: "queued",
      id: submit.json.data.id,
      url,
      message: "URL submitted to VirusTotal for analysis. Poll /api/vt-analysis with this id for the result."
    });
  } catch (err) {
    res.status(502).json({ error: "NETWORK_ERROR", message: String((err && err.message) || err) });
  }
};
