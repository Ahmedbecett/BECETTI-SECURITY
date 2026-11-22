// Real, non-faked health check for the AbuseIPDB proxy: confirms the
// server has ABUSEIPDB_API_KEY configured and that AbuseIPDB actually
// accepts it, by making one real, cheap, read-only lookup (a loopback
// address — a constant, not a secret, and never a real abuse target).
// Never reports "configured"/"reachable" without having actually checked.
const { getApiKey, setCors, abuseIpDbFetch } = require("./_abuseipdblib");

// 1.1.1.1 — Cloudflare's public DNS resolver. A stable, well-known, always-reachable
// address used only to probe that the key is accepted.
const PROBE_IP = "1.1.1.1";

module.exports = async (req, res) => {
  setCors(res, "GET");
  if (req.method === "OPTIONS") {
    res.status(204).end();
    return;
  }

  const apiKey = getApiKey();
  if (!apiKey) {
    res.status(200).json({ configured: false, abuseIpDbReachable: false });
    return;
  }

  try {
    const result = await abuseIpDbFetch(apiKey, `/check?ipAddress=${PROBE_IP}&maxAgeInDays=1`);
    const keyValid = result.status !== 401 && result.status !== 403;
    res.status(200).json({
      configured: true,
      abuseIpDbReachable: keyValid,
      httpStatus: result.status
    });
  } catch (err) {
    res.status(200).json({ configured: true, abuseIpDbReachable: false, error: String((err && err.message) || err) });
  }
};
