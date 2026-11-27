# Dependency and license acceptance

This is an evidence collection step, not an SPDX classifier, license clearance, SBOM or production approval. Run from a trusted clean disposable checkout with Go 1.26.x, Node >=20 and normal authenticated Go checksum verification:

```sh
node --test scripts/dependency-license-evidence.test.mjs
node scripts/validate-release.mjs --mode=lock-only
```

Alternatively dispatch the existing manual release-validation.yml workflow in lock-only mode while the repository is private. No new automatic trigger, deployment or Cloudflare service. The tool independently resolves both modules with go mod tidy; a failed first module does not prevent the second from being attempted. Review each result and only use successfully reproduced lock candidates. Do not fabricate sums or copy an upstream project's entire go.sum.

The private output includes report.json, lock-candidate/{registry,tuf-client}/{go.mod,go.sum} where available, and dependency-licenses/inventory.json plus SHA-256-named license evidence text files. Graph collection uses the selected module graph returned by go list -m -mod=readonly -json all. Each row records module path, selected version, direct/indirect flag, graph membership, status and candidate top-level license/notice filenames, lengths, SHA-256 hashes and evidence filenames. Identical module versions share copied files across graphs. No absolute module cache paths are recorded in the inventory. The main project and its expected local replacement are marked separately; unexpected replacements require review.

A missing source directory, missing top-level license, symlink, oversized license or unknown replacement does not imply license absence or approval. Inspect separately. Module graph membership is not a determination that a dependency is linked into a released binary. Some graph-only modules have no local source; the collector intentionally does not fetch extra source archives. Inspect exact independently verified versions for unresolved rows, nested/package-specific licenses, bundled assets, attribution, patent or redistribution obligations, and licenses inherited from upstream repository roots. Review actual binaries/platforms and direct/transitive dependencies separately. Keep records private until their publication rights are confirmed.

Suggested manual review fields: module path/version, verified source identity, applicable license identifier(s), license text digest(s), required notices, distribution scope, reviewer, review date, unresolved issues. Retain final reviewed notices in a separate PR after approval. Do not label all dependencies MIT merely because this project is MIT.

The collector is bounded to 2,000 module rows per graph, 32 candidate files per module, 512 KiB per file and 32 MiB copied evidence. It does not recursively scan source or execute dependencies. It assumes a trusted local Go toolchain and module cache. All evidence rows remain advisory and licenseReviewComplete stays false. A successful lock-only run means dependency resolution completed, not that the project compiles. Follow with committed-lock validation and independent rights/security review before changing visibility.

At this milestone the root go.sum exists but tools/tuf-client/go.sum is missing. The current execution environment has Go 1.23.2 and cannot resolve proxy.golang.org; the Go 1.26 lock candidates and actual dependency graph remain outstanding. The two new Node fixture tests passed on Node 22.16.0 using local copies matching the committed Git blob hashes. Full Go and workflow execution not performed.
