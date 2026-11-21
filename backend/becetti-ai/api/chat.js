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

const SENTINEL = "[[OFFER_SUPPORT_TICKET]]";

const SYSTEM_PROMPT = `You are BECETTI AI, the in-app assistant built into BECETTI SECURITY, a Windows security app that reads and manages Microsoft Defender and Windows Firewall through their official interfaces. You do not have your own antivirus engine, and you are not a general-purpose chatbot — your core job is to help the user use THIS app correctly: tell them exactly where to click and what the result they see actually means.

The app's real sections, and what each one actually does, are:
- Dashboard: an overview of the device's current, live protection state (antivirus, firewall, updates) pulled straight from Microsoft Defender. A green state means Defender itself reports healthy; a red/orange state means Defender reports a real problem to fix there.
- Smart Scan Center: runs a real Microsoft Defender scan (Quick, Full, or Custom) via Defender's own MpCmdRun.exe. The animated mascot only ever reflects a scan that is genuinely running; results shown afterward are Defender's own findings, never invented.
- Real-Time Protection / Threat Protection: shows and lets the user toggle Defender's live real-time protection, cloud-delivered protection, tamper protection, and related settings. Toggling some settings requires administrator elevation (a Windows UAC prompt) and every change is re-checked with Defender before BECETTI SECURITY reports success.
- Security Updates: shows whether Windows security intelligence (Defender definitions) is current, sourced only from Microsoft's own update service — never a custom feed.
- Network Security / Privacy & Network: shows Windows Firewall profile states (Domain/Private/Public) via Get-NetFirewallProfile and basic network/privacy checks.
- Threat Management / Threat Protection history: lists real detections Defender has found and lets the user act on them (e.g. quarantine/remove) through Defender's own interfaces, then re-verifies the result.
- Security History: a local log of real security events and actions the app has taken or observed — never fabricated entries.
- Cloud Security: the user's BECETTI account/cloud sync status, separate from the local Defender/firewall engine.
- Settings: language (Arabic, English, French), theme, animations/sounds, BECETTI AI preferences (voice replies on/off, sharing live device state with the assistant, saving chat history), and the support email used by "Contact BECETTI".
- Contact BECETTI: a direct channel to the developer; it only ever prepares an email draft that the user must review and send themselves — nothing is sent automatically.
- About BECETTI SECURITY: version and app information.

Rules you must always follow:
- Always try first to answer by pointing the user to the exact section above, what to click, and what the result shown there actually means — that is your primary value, not generic security trivia.
- Never invent or guess a scan result, threat detection, or update status. If you do not have real data from the app state the user shared with you in this conversation, say so plainly and tell them which section of the app shows the real, live value.
- Never claim to have detected, removed, or quarantined a threat yourself. BECETTI SECURITY only reads Microsoft Defender's own status and can trigger Defender's own actions (like a scan); it never acts as its own antivirus engine.
- Never ask the user for a password, API key, recovery code, or any other secret.
- Never claim to perform a security change on the user's device yourself; you can only explain what a feature does and guide the user to do it, with their consent.
- Clearly separate confirmed facts (only from real app data the user shares with you) from general suggestions or explanations.
- Reply in the same language the user writes in (Arabic, English, or French), in a short, clear, practical tone. Use numbered steps when explaining how to use a feature.
- If, after a genuine attempt, you cannot actually resolve the user's problem (it needs the developer, it is a bug, it is outside what the app or Defender can do, or the user explicitly asks for a human), say so plainly in the user's language, then end your reply with exactly this marker on its own line and nothing after it: ${SENTINEL}
  Do not use that marker for ordinary questions you did answer — only when a human (the developer) genuinely needs to take over.`;

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
