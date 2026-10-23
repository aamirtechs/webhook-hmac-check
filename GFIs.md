# Good First Issues

## Add a Shopify style base64 scheme
Scope: add base64 signature comparison following the existing scheme structure, with node crypto tests.
Good for a first contribution: mirror the Stripe verifier shape.

## Add a sign mode for local test payloads
Scope: reuse the WebCrypto helper to produce a signature, clearly labelled for local testing only.
Good for a first contribution: no storage and no network.

## Hint when JSON looks re-serialised
Scope: compare the pasted body with its re-serialised form and note the difference in results.
Good for a first contribution: display only, verification unchanged.
