// Real, non-faked health check for the BECETTI AI backend: confirms the
// server has a Gemini key configured and that Gemini actually accepts it,
// by making one real, cheap, read-only call (list models). Never reports
// "configured"/"reachable" without having actually checked.

module.exports = async (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");

  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) {
    res.status(200).json({ configured: false, geminiReachable: false });
    return;
  }

  try {
    const r = await fetch("https://generativelanguage.googleapis.com/v1beta/models", {
      headers: { "x-goog-api-key": apiKey }
    });
    let modelCount = null;
    if (r.ok) {
      const d = await r.json().catch(() => null);
      modelCount = d && Array.isArray(d.models) ? d.models.length : null;
    }
    res.status(200).json({ configured: true, geminiReachable: r.ok, httpStatus: r.status, modelCount });
  } catch (err) {
    res.status(200).json({ configured: true, geminiReachable: false, error: String((err && err.message) || err) });
  }
};
