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


## Registry Explorer — Cloudflare Workers deployment (v0.4)

Deploy to trust.m78u.com using Workers Static Assets and Wrangler, not a persistent server. Proposed web/ subproject uses TypeScript and static HTML/CSS/JS (Vite if useful); Go builds the read-only public projection from an already authenticated registry release. CI publishes only approved redistributable records. Pre-render certificate pages and shard search indexes as needed; browser-side search by fingerprint, authority, subject, issuer and policy avoids transmitting search terms by default. No D1, KV, login, uploads, or dynamic certificate verification in the initial deployment.

Use wrangler.jsonc with assets.directory pointing to generated web/dist and the custom domain. Configure build-time checks against Workers static-asset limits (currently 25 MiB per file; check count and total deployment budget against the selected plan), and split indexes or use R2 for larger immutable versioned snapshots if necessary. Initially link to GitHub Releases; add an R2 mirror only when needed. Cache versioned artifacts immutably; mutable latest pointers and emergency notices must have short caching or revalidation. Treat transport/cache as untrusted; the SDK verifies independent release metadata, hashes, expiry and rollback state.

Separate Explorer deployment credentials from release signing credentials. Workers never holds release signing keys; site deployments cannot approve trust, alter signed snapshots or bootstrap SDK release roots. No user documents or private keys are uploaded. Apply restrictive CSP and safe rendering of certificate metadata; no third-party analytics by default. Use canonical approved SVG product assets from M78U/brand-assets, copied at a reviewed revision with explicit permission; no private-repo credentials in browser assets. Do not deploy a production Explorer or trust dataset before v0.3 distribution safety gate.

References: https://developers.cloudflare.com/workers/static-assets/ ; https://developers.cloudflare.com/workers/platform/limits/ ; https://developers.cloudflare.com/r2/buckets/public-buckets/
