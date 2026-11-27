# Registry Explorer research preview

Cloudflare Workers Static Assets at [trust.m78u.com](https://trust.m78u.com/), reported deployed by the operator on 2026-11-27. No server-side code, database, KV, R2, uploads, analytics, APIs, or external font requests. Browser search runs on a generated local data module, not an HTTP search endpoint. No runtime dependencies. Node >=20. No Wrangler dependency vendored; deployment operator uses a separately installed Wrangler, or configured Workers Builds. Automatic PR CI remains disabled.

```sh
cd web
npm test
npm run build
# after explicit review and Cloudflare account/domain configuration:
wrangler deploy --config wrangler.jsonc
```

Cloudflare build settings (if manually connected): root directory web; build command npm run build; deploy command npx wrangler deploy --config wrangler.jsonc. For reproducible production deployment pin and review Wrangler first. Config declares custom domain trust.m78u.com and disables workers.dev and preview URLs. This document does not perform deployment. Review domain ownership and site publication rights before deploying. The preview is noindex (robots and headers); this is not access control. Use Cloudflare Access or a private local preview if confidentiality is required.

Only four explicit committed public-research source files are read by the build (SHECA, SATL, endpoint catalog and multi-ca.json); allowlisted scalar fields are projected. No arbitrary inventory, DER, PEM, TUF repository, private signer, decisions or original download URLs are included. SHA-1 is a legacy publisher claim, SHA-256 a third-party lead, and SATL names are not identity or membership. The four CN templates are empty display templates, not policy release artifacts. Research graph edges represent source/claim/name associations only; cryptographic issuer edges require actual certificate bytes and publication authorization. The UI uses textContent and fixed source links; no inline script/style or HTML interpolation. Strict CSP, same-origin static assets, no form submission, no third-party requests, revalidation cache headers. Site is a research directory, never a trust bootstrap. Static output file allowlist and 25 MiB per-file cap. A failed build leaves partial dist; do not deploy unless build completes.

Brand: web/src/icon.svg is a vector reconstruction from the separately maintained M78U brand assets. This is a development preview asset, still pending final vector review and public-use permission check. Raster hero and reference are maintained separately; do not substitute generated artwork or imply final visual signoff. Palette follows Night/Planet/Ring/Star. System fonts until canonical wordmark/typography assets available. No redistribution license is granted by copying into the private development repository.

References: https://developers.cloudflare.com/workers/static-assets/ ; https://developers.cloudflare.com/workers/static-assets/headers/ . Tests cover the projection and filters, not browser rendering. Production data release, graph exploration, approved branding and actual deployment are separate gates.

## Evidence constellation

The interactive evidence graph is derived from the same allowlisted catalog projection. Nodes are directory entries, source pages, indexed SATL names and third-party fingerprint claims. Only eight explicit undirected evidence edge types exist; never derive issuer, identity, membership, trust or transitive links from labels or shared source. The selected node's direct neighbors are drawn using the brand palette; SVG nodes are keyboard-selectable, with a complete parallel button list. At most 12 visible neighbors per constellation, all direct neighbors listed. Filter by relation type, open catalog detail or follow a fixed external source link. All state stays in the browser; no added dependencies or API. Graph contains zero verified issuer edges; future cryptographic graph must be a distinct approved projection of actual DER validation results. Graph model tests check endpoint integrity, deterministic projection, direct adjacency and zero trust elevation.

After any TUF release is deployed, never deploy preview-only dist to the same hostname: it would drop immutable history. Use the separate reviewed static publication workflow in STATIC-PUBLICATION.md, with all TUF history and fresh Explorer assets. Preview-only development must remain local or use a separate nonproduction hostname.

## Multi-CA research preview

One generated data.js contains 32 research rows: 17 SHECA, 4 CFCA, 6 BJCA, 5 GDCA, including seven chain listings and eight total SHA-256 leads (not verified certificate identities). No extra HTTP request, server scan, write or binding. Authority, record type/role, research track, observation status and keyword filters compose locally; labels distinguish official related policy pages and search-index-only observations. No unknown expiry, root role or SHA-1 is inferred for the new rows. Fixed source allowlists bind authority and claim scope; unknown/private fields are discarded. Existing SATL name associations remain SHECA-only; do not infer additional links by matching names. Chain listing and certificate-name evidence edges join only their actual source pages, and independent claim nodes retain scope. Current model 59 nodes, 67 edges, zero verified issuer edges; same 12-neighbor visual cap and complete keyboard-accessible direct relation list. Generated data module capped at 256 KiB; existing asset names and release allowlist unchanged. Seven test cases passed in adapted JS harness against actual repository fixtures; native Node build/browser and Go tests still pending. No signed data deployment or production trust.
