# Homebrew source-build preparation

The first package candidate is the Registry CLI only (`./cmd/trust-registry`), not the three isolated TUF tools or a production trust dataset. Use a reviewed public version, never a floating branch or a placeholder archive hash. No formula, bottle, GitHub Release or deployment is created by this work.

## Actual package-level license evidence

From a clean checkout, with Go 1.26.x and Node >=20:

```sh
node --test scripts/cli-license-evidence.test.mjs
GOOS=darwin GOARCH=arm64 node scripts/cli-license-evidence.mjs --out=../trust-cli-license-arm64
```

Use a new private directory outside the checkout. Repeat for every supported target and exact build configuration (the collector fixes CGO_ENABLED=0, GOWORK=off, GOFLAGS empty and GOTOOLCHAIN=local). Only the Registry executable is in scope. The script records source revision, dependency lock digests, Go version and GOOS/GOARCH, runs go list -mod=readonly -deps -json and go mod verify, and checks that the checkout remains clean and unchanged. Go may resolve required modules over the ordinary configured Go proxy. Use a trusted local toolchain and cache. No GitHub Actions or Cloudflare calls.

The report includes selected package names, root and ancestor license/notice/PATENTS files (including Go standard library and vendored Go standard library dependencies), SHA-256 and exact copied bytes. It does not copy package source files, absolute cache paths, or scan unrelated dependency directories. Symlink and oversized notice files require manual review. Limits: 10,000 packages, 10,000 directories, 32 candidate names per directory, 512 KiB per file, 32 MiB evidence; incomplete collection fails. Discard partial output. Not a license classifier or full SBOM: source headers, embedded assets, nested files outside ancestor paths, redistribution rights and the applicable exact toolchain still need review. It records no distribution authorization.

The two Node fixture tests passed locally on Node 22.16.0. Actual Go 1.26 collection and brew install are not yet verified.

## Formula gate

Confirm that the release is published (not draft), that the `0.1.0` tag resolves to the reviewed source commit, and that the immutable source archive checksum or Git tag/revision pair is verified independently. The preparation tool is on a later development commit. Use an external detached worktree and explicit revision pin; no copying scripts or modifying the released source is needed:

```sh
git worktree add --detach ../trust-registry-0.1.0 0477dd115adb86f32b6b3ac41a8018bf4b087ade
for arch in arm64 amd64; do
  GOOS=darwin GOARCH="$arch" node scripts/cli-license-evidence.mjs \
    --source=../trust-registry-0.1.0 \
    --expected-revision=0477dd115adb86f32b6b3ac41a8018bf4b087ade \
    --out="../trust-0.1.0-license-$arch"
done
```

Use the same Go toolchain patch version as the proposed Homebrew build. This cross-target evidence collection does not execute Intel binaries or replace native install tests. Source and expected revision are required together. The collector checks the Git root, clean status including untracked files (not ignored files), exact HEAD, tracked regular go.mod/go.sum and unchanged lock hashes. The output must be outside both the tooling and source checkout. Use trusted clean worktrees; this does not defend against concurrent malicious local filesystem changes. Review the resulting inventories and exact notice bytes privately. The new source-selection fixture has not yet been executed in the operator environment.

Complete package-specific notices, platform-specific validation, and a local Homebrew formula install/test before registering the formula in M78U/homebrew-tap. The install should build the reviewed source with pinned Go dependencies, ship all applicable notices, and perform an offline synthetic init/validate smoke test. No CA download, private data, production trust anchor, network update or automatic release job. The existing source-only developer preview is unchanged.
