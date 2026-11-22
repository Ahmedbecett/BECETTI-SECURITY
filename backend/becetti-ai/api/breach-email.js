// BECETTI SECURITY — email data-breach lookup proxy. Forwards to the real,
// free, keyless XposedOrNot breach-analytics API and returns a normalized
// report. Never fabricates a breach or a "clean" result — a "not breached"
// answer only ever comes from XposedOrNot's own documented empty-result
// shape (BreachMetrics/ExposedBreaches both null).
const { XON_BASE, setCors, fetchJson, normalizeEmailBreachAnalytics } = require("./_breachlib");

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

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

  const email = typeof req.query.email === "string" ? req.query.email.trim() : "";
  if (!email || email.length > 320 || !EMAIL_RE.test(email)) {
    res.status(400).json({ error: "BAD_REQUEST", message: "Query parameter 'email' must be a valid email address." });
    return;
  }

  try {
    const result = await fetchJson(`${XON_BASE}/breach-analytics?email=${encodeURIComponent(email)}`);

    if (result.status === 429) {
      res.status(429).json({
        error: "RATE_LIMITED",
        message: "The breach-lookup service's free-tier rate limit was reached. Wait a minute and try again."
      });
      return;
    }
    if (result.status !== 200) {
      res.status(502).json({ error: "UPSTREAM_ERROR", message: `The breach-lookup service returned HTTP ${result.status}.` });
      return;
    }

    const normalized = normalizeEmailBreachAnalytics(email, result.json || {});
    res.status(200).json(normalized);
  } catch (err) {
    res.status(502).json({ error: "NETWORK_ERROR", message: String((err && err.message) || err) });
  }
};
