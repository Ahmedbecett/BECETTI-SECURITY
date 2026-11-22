// Real, non-faked health check for the BECETTI AI backend: confirms the
// server has a Gemini key configured and that Gemini actually accepts it,
// by making one real, cheap, read-only call (list models). Never reports
// "configured"/"reachable" without having actually checked.

// The model chat.js actually calls. Kept in sync manually since this file
// has no shared import with chat.js (two independent Vercel functions).
const GEMINI_MODEL = "gemini-3.8-flash";

module.exports = async (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");

  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) {
    res.status(200).json({ configured: false, geminiReachable: false });
    return;
  }

  let modelsOk = false;
  let httpStatus = null;
  let modelCount = null;
  try {
    const r = await fetch("https://generativelanguage.googleapis.com/v1beta/models", {
      headers: { "x-goog-api-key": apiKey }
    });
    httpStatus = r.status;
    modelsOk = r.ok;
    if (r.ok) {
      const d = await r.json().catch(() => null);
      modelCount = d && Array.isArray(d.models) ? d.models.length : null;
    }
  } catch (err) {
    res.status(200).json({ configured: true, geminiReachable: false, error: String((err && err.message) || err) });
    return;
  }

  // ListModels succeeding does NOT guarantee the actual chat call (generateContent)
  // works — the two use different quota/permission paths. ?deep=1 makes one real,
  // minimal generateContent call with the exact model chat.js uses, so a caller can
  // tell the two apart instead of trusting a healthy-looking ListModels result alone.
  const deep = req.query && (req.query.deep === "1" || req.query.deep === "true");
  if (!deep) {
    res.status(200).json({ configured: true, geminiReachable: modelsOk, httpStatus, modelCount });
    return;
  }

  try {
    const upstream = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_MODEL}:generateContent`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json", "x-goog-api-key": apiKey },
        body: JSON.stringify({ contents: [{ role: "user", parts: [{ text: "ping" }] }], generationConfig: { maxOutputTokens: 5 } })
      }
    );
    const data = await upstream.json().catch(() => null);
    const candidate = data && data.candidates && data.candidates[0];
    const parts = candidate && candidate.content && candidate.content.parts;
    const reply = Array.isArray(parts) ? parts.map((p) => p && p.text).filter(Boolean).join("") : "";

    res.status(200).json({
      configured: true,
      geminiReachable: modelsOk,
      httpStatus,
      modelCount,
      model: GEMINI_MODEL,
      generateContentOk: upstream.ok,
      generateContentHttpStatus: upstream.status,
      generateContentError: upstream.ok ? null : ((data && data.error && data.error.message) || `HTTP ${upstream.status}`),
      generateContentSample: upstream.ok ? (reply || null) : null
    });
  } catch (err) {
    res.status(200).json({
      configured: true,
      geminiReachable: modelsOk,
      httpStatus,
      modelCount,
      model: GEMINI_MODEL,
      generateContentOk: false,
      generateContentError: String((err && err.message) || err)
    });
  }
};
