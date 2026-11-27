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

## Direct observed certificate intake

The same commands now accept a selected `CERTIFICATE_NAME_LEAD` **only** when the embedded catalog marks it OFFICIAL_PAGE_OBSERVED and provides an exact independently published SHA-256. Initially eligible: `gdca-gm-sm2-root` and `gdca-trustauth-r5-root`. Obtain the original file from a source you have personally checked and retain it privately. The official directory page is the asserted provenance context, not proof of a download or actual receipt. No direct endpoint or source authorization is inferred.

```sh
trust-registry sources bundle-plan --id gdca-gm-sm2-root \
  --recorded-at CURRENT_RFC3339 original.cer > plan.json
# Review plan and independently retain its SHA-256 before proceeding.
trust-registry sources bundle-export --plan plan.json \
  --plan-sha256 PLAN_PIN --out private-gdca original.cer
trust-registry sources bundle-apply --archive private-gdca \
  --registry local-registry --plan-sha256 PLAN_PIN \
  --certificate-sha256 MATCHED_DER_SHA256
```

Direct profile is limited to one exact DER or one CERTIFICATE PEM, original <=1 MiB. No PKCS#7, extra certificates or unmatched name leads. Both the existing strict CA-only parser and exact single-certificate audit must succeed; SHA-256, common name and basic constraints must match the selected listing, not merely another member of the same authority. Indexed-only and related-policy entries (including the current BJCA global root and CFCA Identity CA leads) remain ineligible for direct intake. Unchanged chain-listing workflow still allows its existing matched-member selection; no new matching scope there.

Archive files, canonical plan, revalidation, provenance and review-workspace integration reuse the existing format. Old chain plans remain unchanged. Only explicit matched imports, never trust or redistribution approval. Synthetic tests cover accepted DER/PEM, rejection of wrong identity, extra members, missing lead, unobserved source, changed original encoding, wrong pin, catalog change, explicit member selection and repeat import. No actual CA bytes acquired; full Go 1.26 tests pending. No new network or Cloudflare operations.
