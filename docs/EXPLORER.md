# Registry Explorer research preview

Cloudflare Workers Static Assets at planned trust.m78u.com. No server-side code, database, KV, R2, uploads, analytics, APIs, or external font requests. Browser search runs on a generated local data module, not an HTTP search endpoint. No runtime dependencies. Node >=20. No Wrangler dependency vendored; deployment operator uses a separately installed Wrangler, or configured Workers Builds. Automatic PR CI remains disabled.

```sh
cd web
npm test
npm run build
# after explicit review and Cloudflare account/domain configuration:
wrangler deploy --config wrangler.jsonc
```

Cloudflare build settings (if manually connected): root directory web; build command npm run build; deploy command npx wrangler deploy --config wrangler.jsonc. For reproducible production deployment pin and review Wrangler first. Config declares custom domain trust.m78u.com and disables workers.dev and preview URLs. No deployment is performed by this PR. Review domain ownership and site publication rights before deploying. The preview is noindex (robots and headers); this is not access control. Use Cloudflare Access or a private local preview if confidentiality is required.

Only three explicit committed public-research source files are read by the build (SHECA, SATL and endpoint catalog); allowlisted scalar fields are projected. No arbitrary inventory, DER, PEM, TUF repository, private signer, decisions or original download URLs are included. SHA-1 is a legacy publisher claim, SHA-256 a third-party lead, and SATL names are not identity or membership. The four CN templates are empty display templates, not policy release artifacts. No graph edges until actual certificate bytes and publication authorization are verified; only an explicitly labeled name-only cross-reference. The UI uses textContent and fixed source links; no inline script/style or HTML interpolation. Strict CSP, same-origin static assets, no form submission, no third-party requests, revalidation cache headers. Site is a research directory, never a trust bootstrap. Static output file allowlist and 25 MiB per-file cap. A failed build leaves partial dist; do not deploy unless build completes.

Brand: web/src/icon.svg is the unchanged vector reconstruction from private M78U/brand-assets commit 135b1aee0c2149234ba9e72c0b946bf894fc79f0, path projects/trust-registry/icon.svg. This is a development preview asset, still pending final vector review and public-use permission check. Approved raster hero and reference remain in brand-assets; connector cannot fetch binary WebP, so do not substitute generated artwork or imply final visual signoff. Palette follows Night/Planet/Ring/Star. System fonts until canonical wordmark/typography assets available. No redistribution license is granted by copying into the private development repository.

References: https://developers.cloudflare.com/workers/static-assets/ ; https://developers.cloudflare.com/workers/static-assets/headers/ . Tests cover the projection and filters, not browser rendering. Production data release, graph exploration, approved branding and actual deployment are separate gates.
