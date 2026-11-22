// BECETTI SECURITY — VirusTotal file-reputation proxy.
//
// Flow (mirrors how the Windows client is designed to call this):
// 1. The client always computes the file's SHA-256 LOCALLY first (it never
//    needs to send file content just to check a hash) and sends only the
//    hash here. If VirusTotal already has a report for that hash, it is
//    returned immediately — the file itself was never uploaded or shared.
// 2. Only if VirusTotal has no existing report, and the caller explicitly
//    opts in by also sending the file content (fileBase64), is the file
//    uploaded to VirusTotal for a fresh scan. Uploading shares the file
//    with VirusTotal and its partners per VirusTotal's own Terms of
//    Service — the Windows app must show the user a clear warning before
//    taking this step, this proxy does not decide that for them.
//
// Body size: this proxy runs as a normal Vercel Node serverless function,
// whose request body is capped well under VirusTotal's own 32 MB limit for
// direct uploads. We enforce a conservative 3 MB raw-file cap here and
// report FILE_TOO_LARGE honestly rather than silently truncating or
// pretending to scan a file we could not actually send.
const { getApiKey, setCors, vtFetch, upstreamErrorResponse, normalizeAttributes } = require("./_vtlib");

const MAX_UPLOAD_BYTES = 3 * 1024 * 1024; // 3 MB raw file size

function isValidSha256(value) {
  return typeof value === "string" && /^[a-fA-F0-9]{64}$/.test(value);
}

module.exports = async (req, res) => {
  setCors(res, "POST");
  if (req.method === "OPTIONS") {
    res.status(204).end();
    return;
  }
  if (req.method !== "POST") {
    res.status(405).json({ error: "METHOD_NOT_ALLOWED", message: "Use POST." });
    return;
  }

  const apiKey = getApiKey();
  if (!apiKey) {
    res.status(503).json({
      error: "NOT_CONFIGURED",
      message: "VirusTotal integration is not configured on the server yet. The administrator needs to set VIRUSTOTAL_API_KEY."
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
  body = body || {};

  const sha256 = typeof body.sha256 === "string" ? body.sha256.trim().toLowerCase() : null;
  const fileBase64 = typeof body.fileBase64 === "string" ? body.fileBase64 : null;
  const fileName = typeof body.fileName === "string" ? body.fileName.slice(0, 260) : null;

  if (!sha256 && !fileBase64) {
    res.status(400).json({ error: "BAD_REQUEST", message: "Provide at least sha256 (hash lookup) or fileBase64 (upload)." });
    return;
  }
  if (sha256 && !isValidSha256(sha256)) {
    res.status(400).json({ error: "BAD_REQUEST", message: "sha256 must be a 64-character hex string." });
    return;
  }

  try {
    // Step 1: always try a hash-only lookup first when we have a hash — this
    // never uploads the file and costs VirusTotal's quota the least.
    if (sha256) {
      const lookup = await vtFetch(apiKey, `/files/${sha256}`);
      if (lookup.ok && lookup.json && lookup.json.data) {
        const normalized = normalizeAttributes(lookup.json.data.attributes || {}, "file", null, sha256);
        res.status(200).json({ status: "completed", source: "existing_report", sha256, fileName, ...normalized });
        return;
      }
      if (lookup.status !== 404) {
        const mapped = upstreamErrorResponse(lookup, "VirusTotal file lookup failed.");
        res.status(mapped.status).json(mapped.body);
        return;
      }
      // 404 = VirusTotal has never seen this hash. Fall through to upload
      // only if the caller actually sent the file content.
      if (!fileBase64) {
        res.status(200).json({
          status: "not_found",
          sha256,
          fileName,
          message: "VirusTotal has no existing report for this file. Re-submit with the file content to request a fresh scan."
        });
        return;
      }
    }

    // Step 2: upload for a fresh scan (only reached with explicit fileBase64).
    let buffer;
    try {
      buffer = Buffer.from(fileBase64, "base64");
    } catch {
      res.status(400).json({ error: "BAD_REQUEST", message: "fileBase64 could not be decoded." });
      return;
    }

    if (buffer.length === 0) {
      res.status(400).json({ error: "BAD_REQUEST", message: "The decoded file is empty." });
      return;
    }
    if (buffer.length > MAX_UPLOAD_BYTES) {
      res.status(413).json({
        error: "FILE_TOO_LARGE",
        message: `This proxy only accepts direct uploads up to ${Math.floor(MAX_UPLOAD_BYTES / (1024 * 1024))} MB. Larger files can still be checked by SHA-256 hash only (the file itself is not sent).`
      });
      return;
    }

    const form = new FormData();
    form.append("file", new Blob([buffer]), fileName || "upload.bin");

    const upload = await vtFetch(apiKey, "/files", { method: "POST", body: form });
    if (!upload.ok || !upload.json || !upload.json.data) {
      const mapped = upstreamErrorResponse(upload, "VirusTotal file upload failed.");
      res.status(mapped.status).json(mapped.body);
      return;
    }

    res.status(202).json({
      status: "queued",
      id: upload.json.data.id,
      sha256: sha256 || null,
      fileName,
      message: "File submitted to VirusTotal for a fresh scan. Poll /api/vt-analysis with this id for the result."
    });
  } catch (err) {
    res.status(502).json({ error: "NETWORK_ERROR", message: String((err && err.message) || err) });
  }
};
