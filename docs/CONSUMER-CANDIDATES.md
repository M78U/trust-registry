# Offline consumer candidate bundle v1

SigLens can consume a portable JSON file without linking the private Registry or TUF module. The SDK Loaded.DiscoverIssuers wraps existing direct issuer discovery. Loaded.CandidateBundle(input) exports CA candidates reachable via MATCHED graph edges; nil input exports all eligible non-self-issued inventory CAs. A self-issued CA is deliberately omitted (including some legitimate rollover certificates). No input leaf bytes or identifiers, root grants, policy decisions, network calls or source authentication claims. The bundle is a research handoff, not a signed release.

Canonical compact Go struct-order JSON plus LF:
```json
{"schemaVersion":"1","kind":"UNTRUSTED_CA_CANDIDATES","snapshotSHA256":"<64 lowercase hex>","snapshotSequence":1,"certificates":[{"sha256":"<DER SHA-256>","der":"<standard base64 DER>","provenanceIds":["<64 lowercase hex>"]}]}
```
Entries sorted by fingerprint, provenance IDs sorted and distinct. Max 64 CA entries, 1 MiB per DER, 3 MiB aggregate DER, 256 provenance IDs per candidate, 6 MiB encoded. Empty allowed. Only valid CA basic constraints, permitted cert-sign KU where present, no unknown critical extensions; no self-issued entries. Receiver must verify canonical bytes, DER hash, constraints and certificate path independently. Snapshot identity and provenance IDs in this transport are assertions, not verified origin. No new trust roots. Caller must explicitly authorize roots, use appropriate purpose/revocation checks. Export only for local use; redistribution rights remain unreviewed.

```sh
trust-registry snapshot export-candidates --snapshot-sha256 INDEPENDENT_SNAPSHOT_DIGEST --at CURRENT_RFC3339 local-snapshot.json > candidates.json
siglens verify --roots manually-reviewed-roots.pem --registry-candidates candidates.json file.pdf
```
The CLI uses LoadPinnedResearch (digest equality, semantic and time checks; not release authentication); an independently obtained digest is required. SDK users of the experimental TUF loader can export from its already verified view. Candidate bundle itself is unsigned. Tests are synthetic and not executed while CI is paused.
