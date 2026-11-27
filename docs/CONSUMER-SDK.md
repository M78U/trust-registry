# Strict Registry consumer SDK

The Go SDK lives in the existing isolated tools/tuf-client module. It is an opt-in strict consumer, not a production CA trust store. OpenConsumer requires an independently provisioned initial TUF root digest and parsed Review Authority (independently pinned by LoadReviewAuthority or review.ParseAuthority), plus a locally installed strict state. No default trust configuration, network, installation fallback, or automatic refresh. Existing RefreshAndInstall with nonnil ReviewAuthority remains the explicit online update operation. Protect local state/clock; optional MinimumSequence and ExpectedSnapshotSHA256 permit checking an independently retained application checkpoint on open. They do not persist a protected checkpoint or prevent deletion of local history. Refresh itself does not accept these external checkpoint arguments.

```go
authority, err := tuf.LoadReviewAuthority(authorityPath, authorityPin)
// handle err before proceeding
session, err := tuf.OpenConsumer(tuf.ConsumerOptions{
    StateDir: stateDir, InitialRootSHA256: rootPin,
    Authority: authority, MinimumSequence: lastAcceptedSequence,
})
// handle err
info, err := session.Info()
// handle err
bundle, err := session.CandidateBundle(signerDER)
// handle err; pass bundle to SigLens as UNTRUSTED_CA_CANDIDATES
```

Open verifies current installed TUF signatures, links, root history, current cache equality, release credential threshold and snapshot integrity. OfflineVerification records verification start and earliest signed root/timestamp/snapshot/targets or application snapshot expiration, checked again at completion. SDK lifetime is min(15 minutes from verification start, that expiry). Each operation checks wall clock before and after; clock before verification start and expiry fail closed. No background refresh, no timer or polling. A live session is intentionally a detached snapshot, not a live-state handle: it does not detect a later local install, clock manipulation within the window, revoked publication keys or remote updates; explicitly reopen after updating. Never reuse an expired session. No claim that a release is unchanged until expiry. Do not cache positive document trust decisions. Info is a detached scalar copy; distribution authentication and public release approval are true, private evidence verification, overall release trust and CA trust remain unestablished.

Methods: Info, Find, Search, Provenance, DiscoverIssuers, CandidateBundle, EvaluatePolicy, VerifyPath, VerifyPathWithRevocation, Diff, AuthorizationImpact and PathImpact. Exact policy ID/version and explicit cutoffs; knowledge time cannot exceed session verification start for policy/path operations. CandidateBundle retains the existing exact consumer format, no trust anchors, no new fields; Info separately identifies the source. No private report/review reason leakage in diff/impact summaries; local policy evaluation itself remains a private diagnostic. Local path and discovery reuse existing temporary inventory staging; not zero local disk I/O. Search and policy evaluation share validated index. No per-document network calls, Cloudflare bindings or service queries.

Comparisons require two still-live sessions with same independent root and authority and increasing sequence/nondecreasing root version. Diff optionally checks adjacent append-only publication transition. Both sessions must have been verified before comparison knowledge cutoff is exceeded (cutoff <= each verification start). PathImpact derives snapshot pins internally, optional local revocation observations still unauthenticated. They reuse existing bounded offline comparators and revalidate their inputs; no historical session retrieval, expired-version fallback, or proof that actual signed documents are affected. To compare across an expired session use the separate research-only pinned snapshot diagnostic commands; never confuse that with strict consumer authentication.

Integration fixture exercises strict session open, independent checkpoint refusal, lookup/provenance, unchanged candidate format, expiry/clock checks and diff across root rotation. Go tests not executed; isolated module go.sum and complete manual validation still pending. Module currently uses local replace; downstream consumers must explicitly pin compatible revisions of both modules until released. No SigLens code change or production deployment in this PR.
