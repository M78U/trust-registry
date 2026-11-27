# Data model

Schema version 1 is experimental. DER SHA-256 lowercase hexadecimal is the certificate identity; PEM is transport only. Store original DER at registry/certificates/<fingerprint>.der and metadata separately. Derived fields are generated and must be checked against DER. DN display text is not a canonical identity. Serial is a positive hexadecimal integer; SKI/AKI are hexadecimal octets. Distinguish key algorithm, signature algorithm and CA role; self-issued does not establish root trust. Historical certificates remain available.

Provenance records independently bind source URL, institution/type, retrieval time, original file hash, DER hash, review evidence, reviewer/time, policy basis and redistribution permission. Multiple records per certificate are permitted. A retrieval timestamp is an assertion about retrieval, not proof. No redistribution until permitted.

Policy identifies jurisdiction, purpose, version, anchors and intermediate candidates, with explicit constraints. Trust decisions are append-only, reference certificate, policy, role, status, reason and evidence; distinguish recordedAt from effectiveFrom/effectiveUntil. Resolve conflicts deterministically or reject ambiguous records. Expiration, revocation and policy distrust are distinct.

Snapshot contains schema and registry versions, monotonic sequence, publication/expiry timestamps, file hashes, index, policy/decision versions and authenticated metadata. Strict schema and reference integrity checks precede use.

Initial code and two schemas cover candidate metadata and local inventory only; policy, provenance review events and decision documents are now modeled for local evaluation; manifest and general schema engine remain planned.

## Local inventory v0.1 (experimental)

- certificates/<lowercase DER SHA-256>.der — exact DER; certificates/<same fingerprint>.json — canonical generated metadata.
- provenance/<SHA-256 of canonical provenance JSON>.json — independent unverified observation, including recordedAt and original input hash. The ID is the filename, not a self-referential field. Identical observation bytes are idempotent; observations at distinct times or sources remain separate. Original source file is not retained, so the source hash is an assertion until independently checked.
- Canonical JSON here means Go struct field order, MarshalIndent with two spaces, default escaping and one final LF. This is an experimental local storage format, not the future authenticated release format.
- Only CA candidates may be persisted. Inspect can still parse leaf certificates. No network operations or trust decisions.
- Files are installed without overwriting via same-directory temporary files and hard links; the directory is operator-controlled, single writer, no untrusted concurrent mutation. Multi-file import is not transactional and may leave partial state; validation rejects missing pairs, orphan sources, unreferenced certificates and unexpected entries. Do not consume an unvalidated directory for publication. No durability guarantees for power loss.
- Validate recomputes DER and metadata, provenance content addresses, field constraints and reference integrity. It cannot prove source authenticity, original input bytes, certificate path validity or release authenticity. General JSON Schema validation is still pending.

Policy review documents contain a versioned policy, independent review events referencing immutable provenance observation IDs, and scoped decision events. The experimental format is not an authenticated snapshot. See TRUST-POLICY.md for time and supersession semantics.

## Derived index and registry validation

The in-memory index is rebuilt only from a fully validated local inventory. It contains fingerprint, display subject/issuer DN, serial, SKI/AKI, public key/signature algorithm and asserted source hostname postings, plus provenance IDs and certificate-to-observation links. Multiple observations from one host do not duplicate a certificate. Query results are exact intersections ordered by fingerprint; cursor pagination requires the same unchanged view and filters. Display DN matching is never used alone to prove an issuer: discovery still checks exact DER names and signatures. Index is not persisted or a source of authority. SDK indexes are snapshots and must be rebuilt after changes.

Unified validation checks explicitly supplied policy documents against one inventory index, including references, role/scope, time and evidence constraints, duplicate policy ID/version and stable jurisdiction/purpose across versions. It cannot establish completeness of omitted documents or historical continuity without authenticated manifests. The typed strict loader and semantic checks are not a general JSON Schema runtime.
