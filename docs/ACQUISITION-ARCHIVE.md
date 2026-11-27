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

Other initial SHA-256 leads: uca-sm2, unitrust-global-r3. No automatic batch or retries. Legacy-only endpoints require explicit --allow-legacy-only even for reuse. Each invocation reads only the selected local path and uses a per-ID exclusive directory lock, no archive scans. A valid existing record yields zero fetch operations and no record rewrite; missing record allows one application-level fetch operation, existing corrupt/mismatched record fails rather than refreshing. FetchOperations counts successful application fetch operations in receipts, not actual network packets or transport retries. Existing observation reuse is not independently pinned until operator checks the returned digest; it is not fresh network confirmation. For a new observation use a separate private archive directory; never overwrite prior evidence. New record committed via synced temp file and no-replace hard link on a local filesystem. Directory fsync and hostile filesystem protection not provided. A crash may leave a lock or temp file; inspect manually before removing stale lock. No automatic repair/reset. Operator controls directory permissions, source selection and local clock.

Inspect/original/import require an independently retained exact digest and rederive report, raw/DER hashes and current catalog bindings, fail closed on mismatch, no network. On catalog changes old observations remain private evidence but cannot be applied by current tooling; keep the original source revision to reproduce historical checks. Import preserves recorded observation time and original file hash, candidate/redistribution-unreviewed status, validates destination before and after; same observation import is idempotent. Registry writes are not transactional. Private original export requires a new file. No raw archives or private report files in static distribution; no new Cloudflare calls, queries, rows, storage, bindings or paid services. Existing TLS download transport has fixed observed endpoints, no proxy/redirect/compression, 30s timeout, and now 32 KiB response-header limit. Standard transport TLS is not document-signing trust. Tests use synthetic certificates and a fake HTTP transport to verify reuse, exact pin, original provenance, changed source/corruption refusal, lock and failed fetch. Go tests not executed; no actual certificate download or new trust anchor in this PR.
