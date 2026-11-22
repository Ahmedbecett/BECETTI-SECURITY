// BECETTI SECURITY — polls a real VirusTotal analysis (returned by
// /api/vt-url or /api/vt-file) by its id and returns the real, current
// status: still queued/in-progress, or the completed normalized report.
// Never invents a "completed" result before VirusTotal itself reports one.
const { getApiKey, setCors, vtFetch, upstreamErrorResponse, normalizeAttributes } = require("./_vtlib");

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
      message: "VirusTotal integration is not configured on the server yet. The administrator needs to set VIRUSTOTAL_API_KEY."
    });
    return;
  }

  const id = typeof req.query.id === "string" ? req.query.id.trim() : "";
  if (!id) {
    res.status(400).json({ error: "BAD_REQUEST", message: "Query parameter 'id' is required." });
    return;
  }

  try {
    const result = await vtFetch(apiKey, `/analyses/${encodeURIComponent(id)}`);
    if (!result.ok || !result.json || !result.json.data) {
      const mapped = upstreamErrorResponse(result, "VirusTotal analysis lookup failed.");
      if (mapped.status === 404) mapped.body = { error: "ANALYSIS_NOT_FOUND", message: "No analysis exists for this id." };
      res.status(mapped.status).json(mapped.body);
      return;
    }

    const attributes = result.json.data.attributes || {};
    const meta = result.json.meta || null;
    const kind = meta && meta.url_info ? "url" : meta && meta.file_info ? "file" : "unknown";
    const vtStatus = attributes.status || "unknown";

    if (vtStatus !== "completed") {
      res.status(200).json({ status: vtStatus, id, message: "VirusTotal is still scanning. Poll again shortly." });
      return;
    }

    const normalized = normalizeAttributes(attributes, kind, meta, id);
    res.status(200).json({ status: "completed", id, ...normalized });
  } catch (err) {
    res.status(502).json({ error: "NETWORK_ERROR", message: String((err && err.message) || err) });
  }
};
