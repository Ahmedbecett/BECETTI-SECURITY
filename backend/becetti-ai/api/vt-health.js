// Real, non-faked health check for the VirusTotal proxy: confirms the
// server has VIRUSTOTAL_API_KEY configured and that VirusTotal actually
// accepts it, by making one real, cheap, read-only lookup (the SHA-256 of
// an empty file — a constant, not a secret). Never reports
// "configured"/"reachable" without having actually checked.
const { getApiKey, setCors, vtFetch } = require("./_vtlib");

// SHA-256 of a zero-byte file. Used only to probe that the key is accepted;
// a 404 ("no report for this hash") still proves the key itself is valid.
const PROBE_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

module.exports = async (req, res) => {
  setCors(res, "GET");
  if (req.method === "OPTIONS") {
    res.status(204).end();
    return;
  }

  const apiKey = getApiKey();
  if (!apiKey) {
    res.status(200).json({ configured: false, virusTotalReachable: false });
    return;
  }

  try {
    const result = await vtFetch(apiKey, `/files/${PROBE_SHA256}`);
    const keyValid = result.status !== 401 && result.status !== 403;
    res.status(200).json({
      configured: true,
      virusTotalReachable: keyValid,
      httpStatus: result.status
    });
  } catch (err) {
    res.status(200).json({ configured: true, virusTotalReachable: false, error: String((err && err.message) || err) });
  }
};
