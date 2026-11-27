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
