// BECETTI AI — chat proxy.
//
// This runs on Vercel (server side), never inside the Windows app. The
// OpenAI API key lives only in this project's Vercel environment variables
// (OPENAI_API_KEY) and is never shipped inside BECETTI SECURITY or committed
// to source control.
//
// Honesty rules enforced here (mirrors the product's "never fake a result"
// principle): on any upstream failure we return a real error to the caller,
// we never synthesize a plausible-looking reply.

const SYSTEM_PROMPT = `You are BECETTI AI, the in-app assistant for BECETTI SECURITY, a Windows security app that reads and manages Microsoft Defender and Windows Firewall through their official interfaces. You do not have your own antivirus engine.

Rules you must always follow:
- Never invent or guess a scan result, threat detection, or update status. If you do not have real data from the app state the user shared with you in this conversation, say so plainly and tell them which section of the app shows the real, live value.
- Never claim to have detected, removed, or quarantined a threat yourself. BECETTI SECURITY only reads Microsoft Defender's own status and can trigger Defender's own actions (like a scan); it never acts as its own antivirus engine.
- Never ask the user for a password, API key, recovery code, or any other secret.
- Never claim to perform a security change on the user's device yourself; you can only explain what a feature does and guide the user to do it, with their consent.
- Clearly separate confirmed facts (only from real app data the user shares with you) from general suggestions or explanations.
- Reply in the same language the user writes in (Arabic, English, or French), in a short, clear, practical tone. Use numbered steps when explaining how to use a feature.
- If you cannot help after a genuine attempt, say so plainly and suggest the user open "Contact BECETTI" to reach the developer directly, rather than guessing.`;

module.exports = async (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") {
    res.status(204).end();
    return;
  }

  if (req.method !== "POST") {
    res.status(405).json({ error: "METHOD_NOT_ALLOWED", message: "Use POST." });
    return;
  }

  const apiKey = process.env.OPENAI_API_KEY;
  if (!apiKey) {
    res.status(503).json({
      error: "NOT_CONFIGURED",
      message: "BECETTI AI is not configured on the server yet. The administrator needs to set OPENAI_API_KEY."
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

  const incoming = Array.isArray(body && body.messages) ? body.messages : null;
  if (!incoming || incoming.length === 0) {
    res.status(400).json({ error: "BAD_REQUEST", message: "messages[] is required." });
    return;
  }

  // Keep only role/content, cap history length, cap each message size.
  const messages = incoming
    .filter((m) => m && typeof m.role === "string" && typeof m.content === "string")
    .slice(-30)
    .map((m) => ({ role: m.role === "assistant" ? "assistant" : "user", content: String(m.content).slice(0, 6000) }));

  if (messages.length === 0) {
    res.status(400).json({ error: "BAD_REQUEST", message: "No valid messages were provided." });
    return;
  }

  const payload = {
    model: "gpt-4o-mini",
    messages: [{ role: "system", content: SYSTEM_PROMPT }, ...messages],
    temperature: 0.4,
    max_tokens: 700
  };

  try {
    const upstream = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${apiKey}`
      },
      body: JSON.stringify(payload)
    });

    const data = await upstream.json().catch(() => null);

    if (!upstream.ok) {
      res.status(502).json({
        error: "UPSTREAM_ERROR",
        message: (data && data.error && data.error.message) || `OpenAI returned HTTP ${upstream.status}.`
      });
      return;
    }

    const reply = data && data.choices && data.choices[0] && data.choices[0].message && data.choices[0].message.content;
    if (!reply) {
      res.status(502).json({ error: "EMPTY_REPLY", message: "The model returned no content." });
      return;
    }

    res.status(200).json({ reply, model: data.model, usage: data.usage || null });
  } catch (err) {
    res.status(502).json({ error: "NETWORK_ERROR", message: String((err && err.message) || err) });
  }
};
