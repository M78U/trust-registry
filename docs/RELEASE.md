# Release design

Evaluate TUF before designing any custom update protocol. Candidate signing algorithm Ed25519. Bootstrap release trust independently (never accept a key supplied only by the downloaded bundle). Separate release credentials from GitHub credentials. Sign immutable authenticated metadata; verify all content and policy references. Define root rotation, threshold, emergency revocation, expiration, persisted monotonic sequence and atomic installation. Offline historical snapshots must be explicitly selected and cannot replace accepted current state.

CI builds deterministic artifacts from reviewed inputs; do not commit generated bundles to main. No production default trust dataset until this gate is implemented and tested. GitHub Releases first; optional R2 distribution later. Explorer is not a trust authority.

## v0.1 developer preview checklist (not a trust dataset)

- [ ] Final CI on Linux/macOS/Windows: module lock/tidy, verify, vet, test, build, CLI smoke.
- [ ] Review the six embedded Draft 2020-12 schemas, format assertions, duplicate-key rejection and deny-all external reference loader; retain semantic validation.
- [ ] Review synthetic standard/SM2 fixtures, candidate storage, discovery, index, provenance and local policy lifecycle.
- [ ] Confirm project license and third-party license notices; no public release before decision.
- [ ] Confirm main-branch rules/review requirements and release approval.
- [ ] Review release notes and identify exact source commit; choose a version/tag explicitly.
- [ ] If a preview is published, label it developer preview, no real anchors, no trusted dataset and no authenticated update protocol. Do not publish candidate sources without redistribution review.

No release tag, GitHub Release, binary package or production trust bundle is created by this PR. Signed distribution is v0.3.

## Local snapshot implementation

See [SNAPSHOT.md](SNAPSHOT.md). The unsigned local research envelope is a deterministic payload format only, not an update protocol. Do not ship it as trusted roots. Sequence, revision and expiry fields are assertions until independently authenticated. Evaluate TUF before implementing production distribution.

## Development CI and TUF decision

At the project owner's request, automatic pull_request and main push CI triggers are disabled during development. CI remains available through workflow_dispatch with the same three-platform checks. Certificate Research remains independently manual. No automatic validation is implied by an open or merged PR. Before any public release, restore mandatory successful checks and independent review; PR #18 was merged despite failed jobs without available logs.

TUF is the preferred production update architecture (https://theupdateframework.github.io/specification/latest/ and https://theupdateframework.io/docs/metadata/). Its root, targets, snapshot and timestamp roles separate trust bootstrap/rotation, target authorization, consistent versions and expiry. The local JSON envelope should be a TUF target, not a replacement for these roles. Evaluate a maintained Go implementation and lock dependencies when executable tests are available. Production deployment remains blocked until authenticated root bootstrap, threshold/rotation, timestamp/snapshot/targets metadata verification, rollback persistence and atomic installation are implemented and independently reviewed.

The current Ed25519 detached-signature feature is explicitly a local research mechanism, not TUF. It verifies a domain-separated envelope SHA-256 with independently provided public keys, distinct signer threshold, explicit time window and caller-owned checkpoint comparison. It does not set releaseAuthenticated or authorize CA trust, implement root/key rotation, persist rollback state or prevent a frozen still-valid snapshot. Do not deploy it as a production updater.

Local research installation now combines the signed snapshot and checkpoint in append-only records (see SNAPSHOT-INSTALLATION.md). It does not replace TUF metadata/state or prove durability against power loss or deletion of local state. Automatic CI remains disabled by owner request.

Experimental TUF client adapter lives in tools/tuf-client; see TUF-DISTRIBUTION.md. No production root or target has been released; dependency lock, executable tests, application sequence state and publication workflow remain gates.
