// BECETTI SECURITY — password exposure check proxy, using HIBP's real
// "Pwned Passwords" k-anonymity range API.
//
// Privacy model (same one HIBP itself designed and recommends): the client
// hashes the password locally with SHA-1 and sends only the first 5 hex
// characters of that hash here as `prefix`. This proxy forwards just that
// prefix to HIBP, which returns every known suffix (and breach count) that
// shares it — typically several hundred entries. The client then checks
// locally whether its own full hash's suffix is among them. Neither this
// proxy nor HIBP ever sees the full hash or the password itself.
const { HIBP_RANGE_BASE, setCors, fetchText } = require("./_breachlib");

const PREFIX_RE = /^[0-9A-Fa-f]{5}$/;

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

  const prefix = typeof req.query.prefix === "string" ? req.query.prefix.trim() : "";
  if (!PREFIX_RE.test(prefix)) {
    res.status(400).json({ error: "BAD_REQUEST", message: "Query parameter 'prefix' must be exactly 5 hex characters (the first 5 characters of a SHA-1 hash)." });
    return;
  }

  try {
    const result = await fetchText(`${HIBP_RANGE_BASE}/${prefix.toUpperCase()}`, {
      headers: { "Add-Padding": "true" }
    });

    if (result.status === 429) {
      res.status(429).json({ error: "RATE_LIMITED", message: "The password-exposure service's rate limit was reached. Wait a bit and try again." });
      return;
    }
    if (result.status !== 200) {
      res.status(502).json({ error: "UPSTREAM_ERROR", message: `The password-exposure service returned HTTP ${result.status}.` });
      return;
    }

    // Pass the raw "SUFFIX:COUNT\r\n..." list straight through — the match
    // against the caller's own full hash suffix happens on the client,
    // which is the whole point of the k-anonymity model.
    res.status(200).json({ status: "completed", prefix: prefix.toUpperCase(), suffixes: result.text });
  } catch (err) {
    res.status(502).json({ error: "NETWORK_ERROR", message: String((err && err.message) || err) });
  }
};
