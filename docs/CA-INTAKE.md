# Offline CA batch intake (research)

Start with exact original certificate files acquired manually or with the existing explicit `sources fetch` command. This workflow never downloads, modifies catalog entries, verifies actual receipt or grants trust. Store files privately outside Git and web assets; name each file exactly <listingId>.cer (single DER or PEM). Only explicitly selected embedded SHECA endpoint IDs are supported, not arbitrary URLs or paths. Default restricts intake to entries with an embedded independent published SHA-256 lead; legacy-only intake requires explicit --allow-legacy-only. SHA-1 is only a historical catalog cross-check. Neither published fingerprint match nor CA classification establishes legal identity, document-signing authorization or permission to redistribute.

Initial candidates with embedded SHA-256 leads are uca-global-g2, uca-sm2 and unitrust-global-r3. Their reference scopes are TLS/SM root-store observations, not document trust. Acquire each using its actual observed endpoint. Example local workflow (use real observation time):
```sh
mkdir -m 700 private-ca
trust-registry sources fetch --id uca-global-g2 --out private-ca/uca-global-g2.cer
trust-registry sources fetch --id uca-sm2 --out private-ca/uca-sm2.cer
trust-registry sources fetch --id unitrust-global-r3 --out private-ca/unitrust-global-r3.cer
trust-registry init --registry local-registry
trust-registry sources intake-plan --dir private-ca \\
  --id uca-global-g2 --id uca-sm2 --id unitrust-global-r3 \\
  --recorded-at CURRENT_RFC3339 > intake-plan.json
# Review plan, retain exact SHA-256 independently (e.g. shasum -a 256 on macOS).
trust-registry sources intake-apply --dir private-ca --registry local-registry \\
  --plan-sha256 REVIEWED_PLAN_SHA256 intake-plan.json
```
Each plan binds canonical parsed catalog and endpoint collection hashes, selected listing IDs, exact original file and DER hashes, source URLs, published fingerprint results, legacy flag and asserted UTC observation time. Exact compact JSON+LF bytes form the plan digest; no manual edits. The SHA-256 pin is an operator-held byte-integrity reference, not a signature or proof of origin. Choose one observation time appropriate to the batch; create separate plans for different observations. The same plan can be applied again, preserving its original time and source/raw hash (no duplicate provenance writes). Changes to any source catalog, original input encoding or selected item reject the old plan. All candidate files are loaded and schema/identity checks completed before any inventory write; destination must already pass Validate. Import uses existing content-addressed CA storage, not an all-or-nothing transaction. An I/O failure can leave partial completed imports or an incomplete inventory. JSON report includes completed imports when possible. Inspect/recover interrupted writes according to store documentation; do not reset inventory. Single operator/writer only; protect directories and clock. Preflight reads only selected known filenames, rejects symlink files and leaf directory, max 32 inputs/16 MiB total/1 MiB each, 256 KiB plan. No pruning, runtime DB, network calls or Cloudflare resources. Plan and report remain private; eventual snapshot must still pass full CA review and redistribution gates.

Synthetic tests exercise repeatable plans, source/byte mismatch, no writes before preflight, duplicate/traversal rejection, same-plan retry and explicit legacy opt-in. Actual CA bytes have not been acquired in this PR. Manual release validation workflow introduced in #40 has no observed run for main yet; TUF go.sum remains missing. Go tests not executed locally (Go 1.23.2, dependency network unavailable). Do not publish real CA or production keys before executable tests and independent review.
