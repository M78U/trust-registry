# Manual developer release validation

The main module and independent tools/tuf-client module need separate dependency locks. The TUF module has no committed go.sum at the start of this work; do not confuse a successful main-module build with a working client/publisher. Go 1.26.x (or compatible newer toolchain) and Node >=20, Git, public Go dependency network access and local temporary filesystem are required. No Go toolchain is automatically downloaded by the script. The script uses standard Node libraries and no npm dependencies. It invokes both modules independently (GOWORK=off), keeps module checksum verification enabled, and does not run certificate-research network acquisitions or any Cloudflare command.

## Resolve dependency locks without compiling (lock-only)

Use a clean disposable worktree and the required Go toolchain:

```sh
node scripts/validate-release.mjs --mode=lock-only
```

This mode invokes real `go mod tidy` separately for both modules, attempts both even if the first fails, then captures selected module graphs using `go list -m -mod=readonly -json all`. It preserves actual generated lock candidates in the report directory even on failure. Success is `LOCK_CANDIDATE_RESOLVED_NOT_TESTED`, not a test pass. Review and commit generated locks in a dedicated PR; never commit partial candidates from a failed module without reproducing resolution successfully. See [dependency license evidence](DEPENDENCY-LICENSE-EVIDENCE.md).

## First run: resolve and test lock candidates

Use a clean disposable branch/worktree. From repository root:

```sh
node scripts/validate-release.mjs --mode=lock-candidate
```

This explicitly permits go mod tidy to modify go.mod/go.sum in both modules. Review exact dependency changes, module versions, checksum records and licenses before committing them in a separate reviewed PR. The report copies existing/generated lock files to a private output folder, even if later validation fails. It never commits, uploads to GitHub itself or claims locked acceptance. A successful candidate run returns LOCK_CANDIDATE_VALIDATED_NOT_COMMITTED.

## Committed-lock acceptance

After both sets of module files are reviewed and committed, from a clean checkout:

```sh
node scripts/validate-release.mjs --mode=locked
```

The script requires tracked go.mod/go.sum for both modules, checks tidy -diff, verify, vet, fresh tests and build under readonly module mode; builds all four actual CLI executables in a temporary directory and checks empty-inventory init/validate, unsigned snapshot integrity and tamper refusal, empty review gate refusal and missing arguments. It runs the audit-tool tests and actual Explorer tests and build using Node directly. It guards the scriptless release config against new runtime bindings, checks that dependency hashes and checkout are unchanged, and records stage results, exact source revision, mode, and dependency hashes. Successful locked run is LOCKED_DEVELOPER_VALIDATION_PASSED, not production authorization. Failure exits nonzero, writes report.json when possible, and stops. Scratch synthetic inputs/binaries are removed. Explorer build regenerates ignored web/dist; do not point at a production deployment directory. Optional --report-dir=NEW_DIR (parent exists) saves the private report in a known location. Default is a new OS temp directory. Never publish validation artifacts or lock candidates as static assets.

## GitHub manual entry point

After this workflow is merged to the default branch:
```sh
gh workflow run release-validation.yml --repo M78U/trust-registry --ref main -f mode=lock-only
# Or resolve and run all tests in one candidate run:
gh workflow run release-validation.yml --repo M78U/trust-registry --ref main -f mode=lock-candidate
# After reviewed lock commit:
gh workflow run release-validation.yml --repo M78U/trust-registry --ref main -f mode=locked
```
One Ubuntu job only, on demand, 30-minute job budget. Read-only GitHub token; no signing/deployment credentials, cloud bindings, automatic PR checks or push trigger. While the repository is private, the artifact contains the report, candidate lock files and local license evidence, retained 7 days; inspect logs on failure. The workflow skips artifact upload for public repositories; use private local review instead. Audit earlier artifacts separately before changing visibility. Existing three-platform CI remains manual-only and is separately needed before release. Do not restore automatic checks without owner approval. No CI run is triggered by adding or merging this workflow.

## Integration scope

The expanded synthetic TestReviewedPublication uses actual prepared static directory files (both successive versions), local TLS, threshold approvals, immutable ledger history, root rotation, strict-client installation, offline load, and replay of a prior static deployment. Existing negative tests cover missing signatures, downgrade, malformed input, expiry and history gaps. Local TLS is a fixture, not Cloudflare edge behavior. The release config uses auto-trailing-slash for the Explorer root index while retaining not_found_handling=none (missing numbered root must remain a genuine HTTP 404, no SPA fallback). Reference: https://developers.cloudflare.com/workers/static-assets/routing/advanced/html-handling/ . Edge routing and cache headers need real smoke checks before production. The validation script checks config only and introduces zero Cloudflare calls.

This PR cannot claim Go tests passed: execution environment lacks Go 1.26 and dependency network access. Explorer test logic was exercised with actual sources/fixtures via an adapted JS harness, not the native Node test runner. The manual workflow must be dispatched by an authorized operator; no real CA data, root keys, release tag or deployment. See RELEASE.md for independent human review, licensing, CA review and live publication gates.
