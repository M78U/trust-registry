# Offline CA acquisition coverage

Run against an initialized private candidate inventory:

```sh
trust-registry sources acquisition-coverage --registry local-registry > private-coverage.json
```

This command derives a deterministic task list from the embedded SHECA catalog, observed endpoint list and CFCA/BJCA/GDCA catalog. All three parsed catalog SHA-256 digests are recorded. One validated in-memory inventory index is reused for exact SHA-256 searches and provenance lookup; no per-row inventory scan, network request, download, import, persistent index or Cloudflare operation. The report can include local inventory observations, so retain it privately outside Git and public assets. The operator must protect the inventory from concurrent mutation. A missing or invalid inventory fails instead of appearing empty. An initialized empty inventory is valid.

## Current routes

| Route | Current catalog rows | Explicit next step |
| --- | ---: | --- |
| PINNED_ENDPOINT_ARCHIVE | 3 | SHECA archive-fetch, inspect and import with independent archive pin |
| PINNED_SINGLE_CERTIFICATE_ARCHIVE | 2 | Obtain original GDCA certificate and use bundle-plan/export/apply |
| EXPLICIT_LEGACY_ONLY_RESEARCH | 8 | Seek independent SHA-256; legacy-only acquisition requires separate explicit opt-in |
| RESEARCH_DOWNLOAD_ENDPOINT | 6 | Verify official download source |
| MANUAL_CHAIN_BUNDLE_RESEARCH | 7 | Obtain original chain, plan matched-member intake |
| RESEARCH_OFFICIAL_SOURCE | 3 | Verify official directory/name association |
| RESEARCH_EXACT_FINGERPRINT | 3 | Obtain independent exact SHA-256 evidence |

Counts describe catalog rows, not distinct certificates or approved anchors. SATL name-only leads are excluded (they are a separate research catalog, not acquisition listings). Routes do not change automatically based on local inventory membership and do not authorize any action.

## Coverage semantics

- Of 32 rows, eight currently have published SHA-256 leads. Only those are eligible for an exact inventory comparison; legacy SHA-1 and names are not used as identity.
- EXACT_FINGERPRINT_PRESENT indicates local validated DER identity only. It does not re-run source intake checks (including SHA-1, CN and context) or prove actual receipt.
- MatchingSourceAssertions counts local provenance records for that fingerprint whose asserted source URL equals the catalog's exact expected URL. It is not domain-only matching. Shared directory URLs do not prove that a direct single-certificate acquisition occurred; bundle imports can also have that URL. A record can be manually asserted. No source authentication is inferred.
- Without explicit archive references every ArchiveStatus is NOT_CHECKED. Source assertions are not archive evidence. Optional pinned archive inspection is described below.
- No trust, source authentication, redistribution approval, review completion, release authentication or policy grant is inferred from the report. Rows without exact SHA-256 are unmeasured, not missing certificates.

The report is deterministic for unchanged catalogs/inventory, without a generated-at time or local path. It is not an independently authenticated release artifact. See [SHECA acquisition](ACQUISITION-ARCHIVE.md), [bundle intake](CERTIFICATE-BUNDLE-INTAKE.md) and [review workspace](CA-REVIEW-WORKSPACE.md).

Synthetic tests cover catalog route counts, deterministic output, uninitialized inventory, exact fingerprint and same-host-but-different-path provenance separation. Full Go 1.26 execution pending; no actual CA material acquired.

## Explicit private archive coverage

```sh
trust-registry sources acquisition-coverage --registry local-registry \
  --archive private-acquisitions --archive-pin uca-global-g2=ARCHIVE_SHA256 \
  --bundle-pin PLAN_SHA256=private-gdca
```

Replace placeholders with independently retained lowercase digests. At most 32 explicit endpoint references (only with published SHA-256) and four explicit bundle plan references, no recursive discovery. The existing bounded archive validators replay exact original bytes, current catalog bindings and pin checks. Bundle validation checks exact directory membership; the endpoint directory is never enumerated. All invalid selections or archive failures fail the entire command without JSON success output. Legacy-only endpoint archives remain available via the separate existing inspection command, not this coverage extension.

An optional archiveCoverage section lists checked archives, original byte digest, exact eligible member identities, and matched local provenance IDs. Matching derives the canonical provenance content address and checks exact record equality in the same validated index, including original file digest, source URL, recorded time, and all candidate fields. A same certificate and source URL with another observation time or file encoding is not a match. Unique matched provenance IDs are counted once even across multiple supplied plans.

Task ArchiveStatus is NOT_CHECKED for unreferenced rows, PINNED_ARCHIVE_CHECKED for a verified selected archive with no exact local provenance, or PINNED_ARCHIVE_MATCHED_PROVENANCE when at least one exact record matches. A chain listing is marked on the basis of its supplied archive and eligible members; this never asserts completeness of a chain or all observations. Matched member listing rows also receive the status. Unmatched members remain excluded from eligible member links; MemberCount counts all parsed members. No archive file paths or raw original bytes are serialized. The existing exact fingerprint inventory counts remain separate; no trust or source receipt authentication, release or redistribution approval. No writes or network. Without flags the existing output shape is unchanged.

Synthetic tests extend endpoint and bundle fixtures for same-source different-time mismatch, exact record match, unmatched bundle member, duplicate plan, and corrupt archive refusal. Full Go 1.26 execution remains pending.

## v0.2 technical evidence from original certificates

Add `--technical` to the existing explicit pinned archive coverage command. Requires at least one explicit independent archive/plan pin. Reuses the validated original bytes without re-opening archive files or rebuilding inventory. Each selected archive includes researchMembers with exact DER fingerprint and catalog match status. All parsed CA members, including unmatched chain members, participate in the separate research-only graph. They do not become eligible import members or change provenance matches. The graph is limited to the supplied originals, not the whole inventory or a complete CA chain. Nodes deliberately report inInventory=false because graph membership is derived solely from private originals; use the separate inventory coverage for actual inventory presence.

The optional technicalEvidence contains a SHA-256-deduplicated direct issuer graph (exact DER DN, AKI/SKI, raw signature and CA constraints) and per-certificate key usage, EKU, policy OIDs, self-signature, basic constraints, path length and critical extension analysis. Existing graph byte/node/edge limits apply; total unique DER <=32 MiB. No path validation, revocation, purpose authorization, source receipt authentication or trust inference. A verified self-signature is not a trust anchor. A graph edge or absent edge is not a complete path or proof of nonexistence. No raw bytes or local paths serialized. Without the flag existing output remains unchanged. No network, persistence or approval. Synthetic tests exercise same-name wrong issuer, duplicate inputs, stable ordering, unmatched bundle member analysis and separation from eligible import links. Full Go 1.26 tests pending.
