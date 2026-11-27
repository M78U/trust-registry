# Offline certificate bundle intake

Supported: single DER certificate, one or more CERTIFICATE PEM blocks, DER or single PKCS7 PEM containing a certificate-only version-1 degenerate SignedData (id-data, absent encapsulated content, empty digestAlgorithms and signerInfos, X.509 certificate choices only, no CRLs). This deliberately narrow profile does not support general signed CMS, BER indefinite lengths, ZIP/PFX, concatenated DER, other PEM labels or SM2-specific PKCS#7 OIDs. Reject unknown/trailing/nested blocks, non-CA certificates and duplicate DER identities. No signature of the container or valid chain is asserted. Order is original encountered order, not a verified issuer path. Limits 16 MiB original, 32 members, 1 MiB/member, 512 KiB plan. Work is entirely local.

The sources workflow binds an observed CFCA/BJCA chain listing, current catalog hash, original byte SHA-256, exact member DER identities/order and asserted observation time in canonical JSON+LF. It labels members with matching independent published SHA-256, subject CN and authority context as MATCHED_PUBLISHED_LEAD. Unmatched and conflicting context are research-only. A listing is an asserted source page, not proof of download or proof of membership in its chain. A fingerprint match does not establish trust or redistribution permission. Retain the original file privately. Example:

```sh
trust-registry sources bundle-plan --id cfca-document-chain \\
  --recorded-at CURRENT_RFC3339 original.p7b > plan.json
# Independently review and retain exact SHA-256 of plan.json.
trust-registry sources bundle-export --plan plan.json \\
  --plan-sha256 PLAN_PIN --out private-bundle original.p7b
trust-registry init --registry local-registry
trust-registry sources bundle-apply --archive private-bundle \\
  --registry local-registry --plan-sha256 PLAN_PIN \\
  --certificate-sha256 MATCHED_DER_SHA256
```

Export creates a new private directory with original.bin, plan.json and digest-named DER members. No overwrites or network. Apply requires exact archive membership/bytes, rechecks current source catalog and entire original, explicitly selects only matched members, checks inventory before import. Existing registry provenance schema records SourceFileSHA256 of the full original container (not extracted DER), with the asserted source page and same observation time. Preserve archive externally for human review; no raw bundle is added to snapshot or public site. The registry-level ImportBundleCandidates API is a generic local candidate import (like Store.Import); it validates member selection but does not enforce a sources catalog. The dedicated sources CLI enforces matching published leads. All imports remain CANDIDATE / NOT_REVIEWED. Same-plan retry deduplicates immutable files. No transaction: interruption may require manual repair; discard incomplete archive export and repeat to a new directory. No cloud reads/writes or new dependencies. Synthetic tests added for formats, malformed/private/non-CA/duplicate content, original hash provenance, idempotence and archive mutation. Go tests not executed; dependency lock and manual acceptance still pending. No real certificates downloaded/imported or deployed.
