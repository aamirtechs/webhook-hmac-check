"use strict";
// Webhook HMAC Check core logic: pure functions, no DOM, no fetch.
// Node path uses node:crypto. The browser page uses WebCrypto for the live check
// and these same helpers for header parsing, comparison and display.

function nodeCrypto() {
  try { if (typeof require === "function") return require("crypto"); } catch (e) { /* browser */ }
  return null;
}

function hmacHex(algorithm, key, payload) {
  const c = nodeCrypto();
  if (!c) throw new Error("HMAC computation needs node:crypto in tests or WebCrypto in the page");
  const algo = String(algorithm || "sha256").toLowerCase() === "sha1" ? "sha1" : "sha256";
  return c.createHmac(algo, String(key)).update(String(payload), "utf8").digest("hex");
}

function hmacBase64(algorithm, key, payload) {
  const c = nodeCrypto();
  if (!c) throw new Error("HMAC computation needs node:crypto in tests or WebCrypto in the page");
  const algo = String(algorithm || "sha256").toLowerCase() === "sha1" ? "sha1" : "sha256";
  return c.createHmac(algo, String(key)).update(String(payload), "utf8").digest("base64");
}

function constantTimeEqual(a, b) {
  const sa = String(a || ""), sb = String(b || "");
  const c = nodeCrypto();
  if (c && c.timingSafeEqual && sa.length === sb.length) {
    try { return c.timingSafeEqual(Buffer.from(sa, "utf8"), Buffer.from(sb, "utf8")); } catch (e) { /* fall through */ }
  }
  if (sa.length !== sb.length) return false;
  let diff = 0;
  for (let i = 0; i < sa.length; i++) diff |= sa.charCodeAt(i) ^ sb.charCodeAt(i);
  return diff === 0;
}

function normalizeHexSignature(sig) {
  return String(sig || "").trim().replace(/^sha256=/i, "").replace(/^sha1=/i, "").toLowerCase();
}

function parseGithubHeader(header) {
  const s = String(header || "").trim();
  let m = s.match(/^sha256=([a-fA-F0-9]+)$/);
  if (m) return { algorithm: "sha256", signature: m[1].toLowerCase(), valid: true };
  m = s.match(/^sha1=([a-fA-F0-9]+)$/);
  if (m) return { algorithm: "sha1", signature: m[1].toLowerCase(), valid: true };
  if (/^[a-fA-F0-9]+$/.test(s)) return { algorithm: "sha256", signature: s.toLowerCase(), valid: true, bare: true };
  return { algorithm: null, signature: null, valid: false };
}

function parseStripeHeader(header) {
  const out = { t: null, timestamp: null, v1: [], v0: [], valid: false };
  String(header || "").split(",").forEach((part) => {
    const idx = part.indexOf("=");
    if (idx < 1) return;
    const k = part.slice(0, idx).trim(), v = part.slice(idx + 1).trim();
    if (k === "t") { out.t = v; out.timestamp = parseInt(v, 10); if (isNaN(out.timestamp)) out.timestamp = null; }
    else if (k === "v1") out.v1.push(v.toLowerCase());
    else if (k === "v0") out.v0.push(v.toLowerCase());
  });
  out.valid = !!(out.t && out.v1.length);
  return out;
}

function stripeSignedPayload(timestamp, payload) { return String(timestamp) + "." + String(payload); }

function verifyGeneric(payload, key, signature, algorithm) {
  const expected = hmacHex(algorithm || "sha256", key, payload);
  const given = normalizeHexSignature(signature);
  return { valid: constantTimeEqual(expected, given), expected, given, algorithm: String(algorithm || "sha256").toLowerCase() };
}

function verifyGithub(payload, key, header) {
  const parsed = parseGithubHeader(header);
  if (!parsed.valid) return { valid: false, reason: "Header is not in sha256=hex or sha1=hex form", expected: null, given: null, algorithm: null };
  const expected = hmacHex(parsed.algorithm, key, payload);
  return { valid: constantTimeEqual(expected, parsed.signature), expected, given: parsed.signature, algorithm: parsed.algorithm };
}

function verifyStripe(payload, key, header, toleranceSeconds, nowSeconds) {
  const tol = toleranceSeconds == null ? 300 : toleranceSeconds;
  const now = nowSeconds == null ? Math.floor(Date.now() / 1000) : nowSeconds;
  const parsed = parseStripeHeader(header);
  if (!parsed.valid) return { valid: false, reason: "Header needs a t timestamp and at least one v1 value", timestampAgeSeconds: null, withinTolerance: false, expected: null };
  const age = Math.abs(now - parsed.timestamp);
  const within = tol === 0 ? true : age <= tol;
  const expected = hmacHex("sha256", key, stripeSignedPayload(parsed.t, payload));
  const match = parsed.v1.some((v) => constantTimeEqual(expected, v));
  let reason = "Signature matches and the timestamp is inside tolerance.";
  if (!match) reason = "Signature does not match the payload for this timestamp.";
  else if (!within) reason = "Signature matches but the timestamp is outside tolerance (possible replay).";
  return { valid: match && within, signatureValid: match, timestampAgeSeconds: age, withinTolerance: within, expected, reason };
}

function maskDigest(hex) {
  const s = String(hex || "");
  if (s.length <= 12) return s ? s.slice(0, 2) + "........" : "";
  return s.slice(0, 8) + "..." + s.slice(-4) + " (" + s.length + " chars, middle hidden)";
}

function detectEncoding(sig) {
  const s = String(sig || "").trim().replace(/^sha(256|1)=/i, "");
  if (/^[a-fA-F0-9]+$/.test(s) && s.length % 2 === 0) return "hex";
  if (/^[A-Za-z0-9+/]+={0,2}$/.test(s) && s.length % 4 === 0) return "base64";
  return "unknown";
}

const api = { hmacHex, hmacBase64, constantTimeEqual, normalizeHexSignature, parseGithubHeader, parseStripeHeader, stripeSignedPayload, verifyGeneric, verifyGithub, verifyStripe, maskDigest, detectEncoding };
if (typeof module !== "undefined" && module.exports) { module.exports = api; }
if (typeof window !== "undefined") { window.WebhookHmacCheck = api; }
