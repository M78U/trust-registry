# Private certificate acquisition archive

This explicit operator-only workflow connects existing SHECA fixed endpoint download checks to private evidence retention and candidate import. It does not automatically fetch on verification, run on a schedule, or publish any materials. CFCA/BJCA/GDCA still lack verified direct binary acquisition endpoints; use their separate local bundle/individual audit workflows.

Create a dedicated private directory outside Git and website assets. One record per selected listing ID, <id>.json, containing exact original bytes as base64, locally observed UTC time from completed fetch, full structured acquisition report, and SHA-256 of canonical current catalog and endpoints. Archive canonical compact JSON+LF, max 2 MiB, original <=1 MiB. Stored observations are unsigned assertions, not authenticated HTTP receipts or trusted timestamps. Fingerprint matching does not establish source authenticity, certificate trust, or redistribution rights. The original can be independently extracted and inspected.

```sh
mkdir -m 700 private-acquisitions
trust-registry sources archive-fetch --archive private-acquisitions --id uca-global-g2
# Retain returned archiveSHA256 independently, after reviewing it.
trust-registry sources archive-inspect --archive private-acquisitions \\
  --id uca-global-g2 --archive-sha256 ARCHIVE_PIN
trust-registry sources archive-original --archive private-acquisitions \\
  --id uca-global-g2 --archive-sha256 ARCHIVE_PIN --out original.cer
trust-registry init --registry local-registry
trust-registry sources archive-import --archive private-acquisitions \\
  --id uca-global-g2 --archive-sha256 ARCHIVE_PIN --registry local-registry
```

Other initial SHA-256 leads: uca-sm2, unitrust-global-r3. No automatic acquisition or retries; an explicit bounded batch option is described below. Legacy-only endpoints require explicit --allow-legacy-only even for reuse. Each invocation reads only the selected local path and uses a per-ID exclusive directory lock, no archive scans. A valid existing record yields zero fetch operations and no record rewrite; missing record allows one application-level fetch operation, existing corrupt/mismatched record fails rather than refreshing. FetchOperations counts successful application fetch operations in receipts, not actual network packets or transport retries. Existing observation reuse is not independently pinned until operator checks the returned digest; it is not fresh network confirmation. For a new observation use a separate private archive directory; never overwrite prior evidence. New record committed via synced temp file and no-replace hard link on a local filesystem. Directory fsync and hostile filesystem protection not provided. A crash may leave a lock or temp file; inspect manually before removing stale lock. No automatic repair/reset. Operator controls directory permissions, source selection and local clock.

Inspect/original/import require an independently retained exact digest and rederive report, raw/DER hashes and current catalog bindings, fail closed on mismatch, no network. On catalog changes old observations remain private evidence but cannot be applied by current tooling; keep the original source revision to reproduce historical checks. Import preserves recorded observation time and original file hash, candidate/redistribution-unreviewed status, validates destination before and after; same observation import is idempotent. Registry writes are not transactional. Private original export requires a new file. No raw archives or private report files in static distribution; no new Cloudflare calls, queries, rows, storage, bindings or paid services. Existing TLS download transport has fixed observed endpoints, no proxy/redirect/compression, 30s timeout, and now 32 KiB response-header limit. Standard transport TLS is not document-signing trust. Tests use synthetic certificates and a fake HTTP transport to verify reuse, exact pin, original provenance, changed source/corruption refusal, lock and failed fetch. Go tests not executed; no actual certificate download or new trust anchor in this PR.

## v0.2 first real SHECA acquisition batch

Run from a clean current source checkout using Go 1.26 and the committed module locks. The 0.1.0 Homebrew CLI does not have these newer commands.

```sh
go build -mod=readonly -o /tmp/trust-registry-research ./cmd/trust-registry
umask 077
# Use a fresh private workspace outside the repository.
mkdir -m 700 "$HOME/trust-registry-v02"
cd "$HOME/trust-registry-v02"
mkdir -m 700 private-acquisitions
/tmp/trust-registry-research sources archive-fetch-batch --archive private-acquisitions \
  --id uca-global-g2 --id uca-sm2 --id unitrust-global-r3 > acquisition-receipts.json
```

Inspect the receipts and original source context, independently retain each reviewed archiveSHA256, and use archive-inspect / archive-original to review each original. Do not derive approval from the fetch report or treat the pin as proof of actual source. TLS and SM root-list scope does not authorize document signing.

```sh
/tmp/trust-registry-research init --registry local-registry
/tmp/trust-registry-research sources archive-import-batch --registry local-registry \
  --archive private-acquisitions \
  --archive-pin uca-global-g2=REVIEWED_PIN_1 \
  --archive-pin uca-sm2=REVIEWED_PIN_2 \
  --archive-pin unitrust-global-r3=REVIEWED_PIN_3 > import-report.json
/tmp/trust-registry-research validate --registry local-registry
/tmp/trust-registry-research sources acquisition-coverage --registry local-registry \
  --archive private-acquisitions \
  --archive-pin uca-global-g2=REVIEWED_PIN_1 \
  --archive-pin uca-sm2=REVIEWED_PIN_2 \
  --archive-pin unitrust-global-r3=REVIEWED_PIN_3 > coverage.json
```

Replace all pins with independently retained lowercase SHA-256 values. If acquisition is incomplete, inspect completed receipts and errors; rerun the same explicit selection only after understanding the failure. An intact existing archive is reused without network or rewrite. Each command takes at most eight explicit unique SHA-256-backed listing IDs, sorted by ID; no all/default selection, legacy-only batch, new endpoint or automatic retry. Fetch CLI has a five-minute overall deadline and existing 30-second per-request timeout. Stops on first error; partial successful receipts are reported, not a full success; successfulFetchOperations excludes failed requests and transport retries. No pin is automatically accepted. Batch import preflights every selected original and independent pin plus validates the destination before writing any candidate; it reuses the validated original bytes and checks inventory after completion. A later I/O error can leave partial writes; no transaction or automated repair. Same observations are idempotent. Retain all reports privately.

Then perform real certificate relationship/usage analysis and independent source/fingerprint and redistribution review with the existing review workspace. The v0.2 milestone remains incomplete until actual acquired data and evidence are validated; no production defaults, release tag, CA dataset or publication in this PR. No Cloudflare operations. Synthetic fake-transport test covers preflight, interrupted batch, reuse, wrong last pin with zero writes and idempotent exact import. Full Go 1.26 execution pending.
