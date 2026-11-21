// Real, non-faked health check for the BECETTI AI backend: confirms the
// server has an OpenAI key configured and that OpenAI actually accepts it,
// by making one real, cheap, read-only call (list models). Never reports
// "configured"/"reachable" without having actually checked.

module.exports = async (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");

  const apiKey = process.env.OPENAI_API_KEY;
  if (!apiKey) {
    res.status(200).json({ configured: false, openaiReachable: false });
    return;
  }

  try {
    const r = await fetch("https://api.openai.com/v1/models", {
      headers: { Authorization: `Bearer ${apiKey}` }
    });
    let modelCount = null;
    if (r.ok) {
      const d = await r.json().catch(() => null);
      modelCount = d && Array.isArray(d.data) ? d.data.length : null;
    }
    res.status(200).json({ configured: true, openaiReachable: r.ok, httpStatus: r.status, modelCount });
  } catch (err) {
    res.status(200).json({ configured: true, openaiReachable: false, error: String((err && err.message) || err) });
  }
};
