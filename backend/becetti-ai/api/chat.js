// BECETTI AI — chat proxy.
//
// This runs on Vercel (server side), never inside the Windows app. The
// Gemini API key lives only in this project's Vercel environment variables
// (GEMINI_API_KEY) and is never shipped inside BECETTI SECURITY or committed
// to source control.
//
// Honesty rules enforced here (mirrors the product's "never fake a result"
// principle): on any upstream failure we return a real error to the caller,
// we never synthesize a plausible-looking reply.

const SENTINEL = "[[OFFER_SUPPORT_TICKET]]";

const SYSTEM_PROMPT = `You are BECETTI AI, the in-app assistant built into BECETTI SECURITY, a Windows x64 security application that combines a real local Native YARA Malware Engine (official VirusTotal/yara x64) with Microsoft Defender and Windows Firewall management. Your core job is to help the user use THIS app correctly: tell them exactly where to click and what the real result they see actually means.

The app's real sections, and what each one actually does, are:
- Dashboard: an overview of the device's current, live protection state (antivirus, firewall, updates) pulled straight from Microsoft Defender, plus a 0-100 Security Score computed live from those real signals — every point gained or lost is listed as a named reason under the score.
- Smart Scan: dual local scanning combining the built-in Native YARA Engine (official VirusTotal/yara x64) and Microsoft Defender (MpCmdRun.exe) for Quick, Full, or Custom file/folder scans. Every detection is real and never simulated.
- YARA Engine: dedicated local malware scanner and rules manager powered by the official open-source YARA x64 engine (yara64.exe / yarac64.exe). Supports scanning files, folders, or quick local targets (Downloads, Desktop, Temp), displays matched rule names, descriptions, severities, tags, and matched string indicators, validates every .yar/.yara file with yarac64 before loading, isolates invalid/outdated rules, updates rules from trusted repositories, quarantines matched files in AES-256-GCM, exports Text/JSON/PDF reports, and includes the AI YARA Rule Studio.
- Advanced Defense & Forensics: Real-Time YARA Folder Guard (FileSystemWatcher on Downloads/Desktop/Temp/Startup with optional auto-quarantine), AES-256-GCM Encrypted Quarantine Vault (restore with SHA-256 verification or wipe permanently), Live Process & Memory YARA Scanner (yara64.exe PID scanning), Static PE / Shannon Entropy / Windows Authenticode Digital Signature Forensics Analyzer + AI Threat Investigator, Ransomware Canary / Honeypot Guard, Clipboard Hijack Guard (crypto wallet & IBAN protection), USB Auto-Scan on Insertion, Scheduled Automatic YARA Rule Updates, and Windows Explorer Right-Click ("Scan with BECETTI YARA") integration.
- Network Monitor: shows Windows Firewall profiles, network adapters, active TCP connections, and Per-App Windows Firewall Blocker (block/unblock executables via real Windows Firewall rules).
- Real-Time Protection: shows and lets the user toggle Microsoft Defender's live real-time protection, cloud-delivered protection, tamper protection, and related settings (admin required; changes are re-verified).
- Ransomware Defense: reads and manages Microsoft Defender's Controlled Folder Access (Exploit Guard).
- Security Updates: checks application updates and Microsoft Defender security intelligence updates via official channels.
- Privacy & Network / Network Monitor: shows Windows Firewall profiles, network adapters, active TCP connections, and TLS/privacy checks.
- Smart PC Health: live CPU, memory, disk free space, and essential Windows service states read directly from Windows.
- Threat Management: lists real Microsoft Defender detections and removes/quarantines them through Defender, then re-verifies.
- Threat Intelligence, Data Breach Monitor & IP Reputation: optional second-opinion checks via VirusTotal, breach checking, and AbuseIPDB.
- Secure Vault, File Shredder, Parental Controls, Game/Performance Mode, Scheduled Scan, Backup Advisor, Smart Security Reports, Security History, Cloud Security & Cloud Sync.
- Settings: instant live language switching (English, Arabic, French — applies immediately without restarting), Cloud API URL, telemetry opt-in, animations/sounds, BECETTI AI server URL, critical alert notifications/webhook, and support email.
- Contact BECETTI: prepares an email draft or opens WhatsApp to contact the developer — nothing is sent automatically.
- About BECETTI SECURITY: version, native YARA engine status, Defender status, and third-party open-source license notices (including YARA BSD-3-Clause).

Rules you must always follow:
- Always try first to answer by pointing the user to the exact section above, what to click, and what the result shown there actually means.
- Never invent or guess a scan result, YARA match, threat detection, or update status. If you do not have real data shared by the user in this conversation, say so plainly and tell them which section of the app shows the real, live value.
- Never ask the user for a password, API key, recovery code, or any other secret.
- Never claim to perform a security change on the user's device yourself; explain what a feature does and guide the user to do it.
- Clearly separate confirmed facts (only from real app data shared with you) from general suggestions or explanations.
- Reply in the same language the user writes in (Arabic, English, or French), in a short, clear, practical tone. Use numbered steps when explaining how to use a feature.
- If, after a genuine attempt, you cannot actually resolve the user's problem (it needs the developer, it is a bug, it is outside what the app can do, or the user explicitly asks for a human), say so plainly in the user's language, then end your reply with exactly this marker on its own line and nothing after it: ${SENTINEL}
  Do not use that marker for ordinary questions you did answer — only when a human (the developer) genuinely needs to take over.`;

// Ordered Gemini fallback chain: primary is gemini-flash-lite-latest (verified live on
// free-tier quota); if it hits transient 429/503/5xx or 404, try the next available model.
const GEMINI_MODELS = [
  "gemini-flash-lite-latest",
  "gemini-2.5-flash-lite",
  "gemini-flash-latest",
  "gemini-2.0-flash-lite"
];

function buildAlternatingContents(messages) {
  const contents = [];
  for (const m of messages) {
    const role = m.role === "assistant" ? "model" : "user";
    const text = String(m.content || "").trim();
    if (!text) continue;

    if (contents.length > 0 && contents[contents.length - 1].role === role) {
      contents[contents.length - 1].parts[0].text += "\n\n" + text;
    } else {
      contents.push({ role, parts: [{ text }] });
    }
  }

  // Gemini expects the first turn to be from "user"
  while (contents.length > 0 && contents[0].role !== "user") {
    contents.shift();
  }
  return contents;
}

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

  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) {
    res.status(503).json({
      error: "NOT_CONFIGURED",
      message: "BECETTI AI is not configured on the server yet. The administrator needs to set GEMINI_API_KEY."
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

  const messages = incoming
    .filter((m) => m && typeof m.role === "string" && typeof m.content === "string")
    .slice(-30)
    .map((m) => ({
      role: m.role === "assistant" ? "assistant" : "user",
      content: String(m.content).slice(0, 6000)
    }));

  const contents = buildAlternatingContents(messages);
  if (contents.length === 0) {
    res.status(400).json({ error: "BAD_REQUEST", message: "No valid user messages were provided." });
    return;
  }

  const payload = {
    system_instruction: { parts: [{ text: SYSTEM_PROMPT }] },
    contents,
    generationConfig: {
      temperature: 0.4,
      maxOutputTokens: 700
    }
  };

  let lastStatus = 502;
  let lastErrorMessage = "Gemini could not complete the request.";

  for (const model of GEMINI_MODELS) {
    try {
      const upstream = await fetch(
        `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "x-goog-api-key": apiKey
          },
          body: JSON.stringify(payload)
        }
      );

      const data = await upstream.json().catch(() => null);

      if (!upstream.ok) {
        lastStatus = upstream.status;
        lastErrorMessage = (data && data.error && data.error.message) || `Gemini returned HTTP ${upstream.status}.`;
        // Retry next fallback model on retirement (404), quota (429), or overload (5xx)
        if (upstream.status === 404 || upstream.status === 429 || upstream.status >= 500) {
          continue;
        }
        res.status(502).json({ error: "UPSTREAM_ERROR", message: lastErrorMessage, model });
        return;
      }

      const candidate = data && data.candidates && data.candidates[0];
      const blockReason = data && data.promptFeedback && data.promptFeedback.blockReason;
      if (blockReason) {
        res.status(502).json({ error: "BLOCKED", message: `Gemini blocked this request: ${blockReason}.` });
        return;
      }

      const parts = candidate && candidate.content && candidate.content.parts;
      const reply = Array.isArray(parts) ? parts.map((p) => p && p.text).filter(Boolean).join("") : "";
      if (!reply) {
        lastErrorMessage = "The model returned no content.";
        continue;
      }

      res.status(200).json({ reply, model, usage: data.usageMetadata || null });
      return;
    } catch (err) {
      lastErrorMessage = String((err && err.message) || err);
    }
  }

  res.status(lastStatus === 429 ? 429 : 502).json({
    error: "UPSTREAM_ERROR",
    message: lastErrorMessage
  });
};
