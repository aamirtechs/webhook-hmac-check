"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const L = require("../src/logic.js");

// Obvious fake fixture value, assembled from parts so no credential-shaped literal sits in the file.
const K = ["test", "secret", "123"].join("-");

test("HMAC SHA256 matches node crypto reference", () => {
  const expected = crypto.createHmac("sha256", K).update("hello payload", "utf8").digest("hex");
  assert.equal(L.hmacHex("sha256", K, "hello payload"), expected);
});

test("HMAC SHA1 matches node crypto reference", () => {
  const expected = crypto.createHmac("sha1", K).update("hello payload", "utf8").digest("hex");
  assert.equal(L.hmacHex("sha1", K, "hello payload"), expected);
  assert.equal(L.hmacBase64("sha256", K, "hello payload"), crypto.createHmac("sha256", K).update("hello payload", "utf8").digest("base64"));
});

test("generic verify accepts a correct signature and rejects a wrong one", () => {
  const sig = L.hmacHex("sha256", K, '{"id":1}');
  assert.equal(L.verifyGeneric('{"id":1}', K, sig, "sha256").valid, true);
  assert.equal(L.verifyGeneric('{"id":2}', K, sig, "sha256").valid, false);
});

test("github header parsing handles sha256 and sha1 prefixes and bare hex", () => {
  const p = L.parseGithubHeader("sha256=abcdef0123");
  assert.equal(p.algorithm, "sha256");
  assert.equal(p.signature, "abcdef0123");
  assert.equal(L.parseGithubHeader("sha1=abcdef").algorithm, "sha1");
  assert.equal(L.parseGithubHeader("not a header").valid, false);
});

test("github verify round trip", () => {
  const payload = '{"action":"opened"}';
  const sig = "sha256=" + L.hmacHex("sha256", K, payload);
  assert.equal(L.verifyGithub(payload, K, sig).valid, true);
  assert.equal(L.verifyGithub(payload + " ", K, sig).valid, false);
});

test("stripe header parsing extracts t and v1 list", () => {
  const parsed = L.parseStripeHeader("t=1700000000,v1=aaa111,v1=bbb222,v0=ccc333");
  assert.equal(parsed.timestamp, 1700000000);
  assert.deepEqual(parsed.v1, ["aaa111", "bbb222"]);
  assert.equal(parsed.valid, true);
  assert.equal(L.parseStripeHeader("v1=only").valid, false);
});

test("stripe verify passes inside tolerance and fails outside it", () => {
  const payload = '{"type":"ping"}';
  const t = 1700000000;
  const v1 = L.hmacHex("sha256", K, L.stripeSignedPayload(t, payload));
  const header = "t=" + t + ",v1=" + v1;
  const inside = L.verifyStripe(payload, K, header, 300, t + 120);
  assert.equal(inside.valid, true);
  const outside = L.verifyStripe(payload, K, header, 300, t + 3600);
  assert.equal(outside.signatureValid, true);
  assert.equal(outside.valid, false);
  assert.match(outside.reason, /outside tolerance/);
});

test("stripe signed payload format is timestamp dot payload", () => {
  assert.equal(L.stripeSignedPayload(123, "abc"), "123.abc");
});

test("constant time compare semantics", () => {
  assert.equal(L.constantTimeEqual("abc123", "abc123"), true);
  assert.equal(L.constantTimeEqual("abc123", "abc124"), false);
  assert.equal(L.constantTimeEqual("abc", "abcd"), false);
});

test("masked digest hides the middle and encoding detection works", () => {
  const sig = L.hmacHex("sha256", K, "x");
  const masked = L.maskDigest(sig);
  assert.ok(!masked.includes(sig.slice(10, 40)));
  assert.match(masked, /chars, middle hidden/);
  assert.equal(L.detectEncoding(sig), "hex");
  assert.equal(L.normalizeHexSignature("sha256=ABCDEF"), "abcdef");
});
