# TUF distribution client — experimental integration

Production direction: The Update Framework (TUF), using upstream go-tuf/v2 v2.4.2, not an in-house metadata verifier. References: https://theupdateframework.github.io/specification/latest/ and https://github.com/theupdateframework/go-tuf/tree/v2.4.2. This PR adds an opt-in client adapter, isolated at tools/tuf-client as a separate Go module. The main module and existing offline CLI/SDK remain unchanged. No publishing server, repository signing keys, initial trusted root, real CA bytes or deployment.

**Build gate:** automatic CI remains suspended. This environment has Go 1.23 and no DNS access to the Go proxy; Go 1.26, dependency resolution, complete go.sum and executable tests are not available. Do not treat this module as release ready. On a connected trusted developer host, cd tools/tuf-client, review upstream advisories and dependencies, run go mod tidy, inspect and commit go.mod/go.sum in a follow-up, go mod verify, go vet ./..., go test ./..., go build ./cmd/tuf-fetch. Run full main-module checks separately. No fabricated checksums. A full signed repository integration test, metadata rotation/rollback tests and platform tests are required before production.

The repository profile is top-level metadata only, fixed target registry-snapshot.json with exactly one SHA-256 hash (allows hash-prefixed consistent snapshot targets). Metadata and targets HTTPS bases must be explicitly configured. No redirect, no proxy inherited from environment, fixed filenames, bounded request count/body/total budget and timeout. go-tuf Refresh implements root rotation, timestamp, snapshot and targets validation. The target must be in top-level targets and pass go-tuf length/hash checks; then the existing Registry snapshot verifier validates its canonical content and semantics plus declared time window. No network in ordinary Registry commands.

Bootstrap requires independently acquired root.json plus its SHA-256 from a separate trusted channel. Do not obtain the initial root pin from the same untrusted download. First use creates a nonexistent private directory (parent exists); subsequent calls omit bootstrap root but require the same initial pin and repository URLs. Reuse protected metadata cache and rotated root, never wipe cache on failure. Cooperating processes use a directory lock. A failed initial bootstrap can leave state; inspect before any recovery. The cache is not tamper-proof and depends on local access controls and reliable system time. Upstream cache persistence does not guarantee directory fsync or power-loss recovery. No unsafe offline metadata mode, no delegated target traversal. A failed update may advance some TUF metadata before target verification; no fallback to an earlier cache.

Example (URLs and pin are placeholders, not a deployed service):
```sh
cd tools/tuf-client
go run ./cmd/tuf-fetch --state "$HOME/registry-tuf" \
  --metadata-url https://trust.example.org/tuf/metadata \
  --targets-url https://trust.example.org/tuf/targets \
  --root-sha256 INDEPENDENT_ROOT_SHA256 \
  --bootstrap-root root.json --out downloaded-snapshot.json
```

Later refresh omits --bootstrap-root and uses a new output path. No automatic installation. The report distinguishes tufTargetAuthenticated from releaseAuthenticated (always false in this experimental adapter) and trustStatus NOT_ESTABLISHED. TUF metadata rollback checks do not guarantee a monotonically increasing application snapshot sequence if a newer signed targets role points at an older envelope; application checkpoint and atomic installation integration remain pending. No approval of CA evidence, policy, redistribution or business purpose. Do not use the TUF target as a production trust store. Never publish private keys to Workers or GitHub.
