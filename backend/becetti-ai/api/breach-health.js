// Real, non-faked health check for the breach-monitoring proxy: makes one
// real, cheap, read-only request to each upstream (XposedOrNot and HIBP's
// Pwned Passwords range API) and reports what actually happened. Neither
// upstream needs an API key, so this always reports "configured": true —
// the field exists for symmetry with /api/vt-health and to leave room for a
// future paid tier that would need a key.
const { XON_BASE, HIBP_RANGE_BASE, setCors, fetchJson, fetchText } = require("./_breachlib");

module.exports = async (req, res) => {
  setCors(res, "GET");
  if (req.method === "OPTIONS") {
    res.status(204).end();
    return;
  }

  const result = { configured: true };

  try {
    // A domain-filtered catalog lookup is the cheapest real read against
    // XposedOrNot's email-breach service (it does not touch the stricter
    // per-IP check-email/breach-analytics quotas).
    const xon = await fetchJson(`${XON_BASE}/breaches?domain=example.com`);
    result.emailBreachServiceReachable = xon.status === 200;
    result.emailBreachHttpStatus = xon.status;
  } catch (err) {
    result.emailBreachServiceReachable = false;
    result.emailBreachError = String((err && err.message) || err);
  }

  try {
    // 5BAA6 is the well-known, publicly documented SHA-1 prefix for the
    // password "password" — not a secret, safe to use as a liveness probe.
    const hibp = await fetchText(`${HIBP_RANGE_BASE}/5BAA6`);
    result.passwordBreachServiceReachable = hibp.status === 200;
    result.passwordBreachHttpStatus = hibp.status;
  } catch (err) {
    result.passwordBreachServiceReachable = false;
    result.passwordBreachError = String((err && err.message) || err);
  }

  res.status(200).json(result);
};
