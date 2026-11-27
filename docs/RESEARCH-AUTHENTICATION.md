# Local research authentication (not a production updater)

Ed25519 signs the ASCII bytes "M78U Trust Registry local research snapshot signature v1", a NUL separator, and lowercase SHA-256 hex of the exact canonical snapshot envelope. Signature file is compact struct-order JSON + LF with schemaVersion, keyId (SHA-256 of raw public key), snapshotSHA256 and base64 signature. No key is embedded in the snapshot or signature file. SignResearch first validates the local research envelope. AuthenticateResearch requires independently supplied public keys, validates distinct signature threshold and verifies all submitted signatures before semantic snapshot validation. Maximum 16 keys/signatures, no duplicates or unknown signers.

The explicit current time must be in [createdAt, expiresAt). An independently maintained caller checkpoint rejects lower sequence and same-sequence different hash. A nil checkpoint is explicit bootstrap; neither CLI nor SDK persists it. The caller must store the returned nextCheckpoint in protected storage scoped to a single research stream, and must provide reliable current time. Do not use attacker-provided time, keys, thresholds or checkpoint. A still-valid old snapshot can be frozen; the protocol cannot check latest availability or safely rotate keys. No production releaseAuthenticated flag is set; certificate trust remains NOT_ESTABLISHED.

Example using locally generated disposable research keys (outside the repository; do not upload private keys, no production signing key):
```sh
umask 077
openssl genpkey -algorithm ED25519 -out research-key.pem
openssl pkey -in research-key.pem -pubout -out research-public.pem
trust-registry snapshot sign-research --key research-key.pem --out research.sig.json local-snapshot.json
trust-registry snapshot authenticate-research --public-key research-public.pem --signature research.sig.json --threshold 1 --at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --bootstrap local-snapshot.json
```
Subsequent verification requires --previous-sequence and --previous-sha256 instead of --bootstrap. Repeat --public-key and --signature for threshold research. CLI accepts unencrypted PKCS#8/SPKI PEM; use protected offline local keys only, never Git, Actions secrets or Cloudflare. No secure hardware signer, key encryption, durable checkpoint, installation or rotation yet. TUF is preferred for production (see RELEASE.md). Tests are included but automatic CI is paused; no claim of passing execution.
