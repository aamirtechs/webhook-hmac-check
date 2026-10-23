# Changelog

## 1.0.0 - 2026-10-23

- Initial release.
- Schemes: generic HMAC-SHA256 and SHA1, GitHub sha256= and sha1= headers, and Stripe style t plus v1 headers with a timestamp tolerance check.
- Paste the raw body exactly as received. Re-serialised JSON changes the bytes and is the top cause of false failures, so the page warns about it.
- Verification uses WebCrypto in the tab with a constant-time comparison, and the expected digest is shown masked.
- Timestamp freshness is reported for Stripe style headers, which helps spot replayed events.
- Fully offline after load: the signing key never leaves the tab, is never stored and never appears in the URL.
