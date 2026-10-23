# Webhook HMAC Check
Live page: https://aamirtechs.github.io/webhook-hmac-check/

Verify a webhook signature locally: paste the payload, the signing key and the signature header, and get valid or invalid for Stripe-style, GitHub and generic HMAC schemes. It solves a recurring, specific job for the people who hit it every week, in one local page with no account and no upload.

## Features
- Schemes: generic HMAC-SHA256 and SHA1, GitHub sha256= and sha1= headers, and Stripe style t plus v1 headers with a timestamp tolerance check.
- Paste the raw body exactly as received. Re-serialised JSON changes the bytes and is the top cause of false failures, so the page warns about it.
- Verification uses WebCrypto in the tab with a constant-time comparison, and the expected digest is shown masked.
- Timestamp freshness is reported for Stripe style headers, which helps spot replayed events.
- Fully offline after load: the signing key never leaves the tab, is never stored and never appears in the URL.

## How it works
Load or paste your input in the tool card, set the options, and run it. All parsing, checking and file generation happens locally in the page, and you download the result (a report, a converted file, or a corrected snippet) straight from the browser. It runs entirely in the browser.

## Privacy
Runs 100% in your browser. Your files never leave this device, nothing is uploaded,
and there is no tracking.

## Development
Core logic lives in `src/logic.js` and is shared by the page and the tests.
Run the tests with `npm test`.

## License
MIT, Copyright 2026 Amir Hussain.
