# Architecture

Official CA repositories, signed lists and public sources -> bounded offline import -> content-addressed DER inventory and independent provenance -> scoped trust policies and append-only decisions -> validated deterministic snapshot -> authenticated distribution -> offline SDK and Explorer.

## Boundaries
- Registry stores public CA material; no CA private keys, user documents, issuance or legal adjudication.
- Inventory is not a trust store. Discovery by fingerprint, normalized DN, AKI/SKI, serial, authority, algorithm and AIA yields candidates only. Verify actual signatures and path constraints before accepting a path.
- Policy authorizes anchors explicitly per purpose and jurisdiction; intermediates are candidates, never implicit anchors. Consumer checks leaf authorization and document signatures.
- Publisher builds from reviewed Git inputs, signs via a separately managed release system. Explorer is a read-only projection, never a trust bootstrap.
- SDK loads authenticated immutable snapshots offline, with explicit evaluation time, policy and audit evidence. No fallback to OS roots.
- Optional network discovery is opt-in and never confers trust.

Go standard library plus planned pinned gmsm/smx509 for SM2; JSON Schema, SHA-256 DER IDs, Git and GitHub Actions. No database or backend initially. GitHub Releases, later Cloudflare Workers and optional R2.

## Integration
SigLens issue #23: preserve explicit roots/intermediates, report crypto validity independently of path trust; report policy, snapshot digest/version, anchor fingerprint, evaluation time and evidence. No automatic trust of embedded roots. Unknown is not forgery. No production defaults before secure distribution.
