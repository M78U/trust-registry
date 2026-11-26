# Release design

Evaluate TUF before designing any custom update protocol. Candidate signing algorithm Ed25519. Bootstrap release trust independently (never accept a key supplied only by the downloaded bundle). Separate release credentials from GitHub credentials. Sign immutable authenticated metadata; verify all content and policy references. Define root rotation, threshold, emergency revocation, expiration, persisted monotonic sequence and atomic installation. Offline historical snapshots must be explicitly selected and cannot replace accepted current state.

CI builds deterministic artifacts from reviewed inputs; do not commit generated bundles to main. No production default trust dataset until this gate is implemented and tested. GitHub Releases first; optional R2 distribution later. Explorer is not a trust authority.
