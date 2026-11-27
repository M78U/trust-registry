# Trust policy

Discovery != provenance verification != scoped trust. Candidate data cannot authorize an anchor.

Provenance states: CANDIDATE, PROVENANCE_VERIFIED, REVIEW_REJECTED.
Decision states: TRUSTED, SUSPENDED, DISTRUSTED; no decision means unestablished trust.

Initial purposes: document-signing, electronic-seal-signing, seal-maker, timestamping. Later: code-signing, device-authentication, client-authentication, server-authentication. No inheritance from TLS or cross-purpose escalation. CA path validity is not leaf authorization.

Default anchor lists are empty. Only explicit reviewed decisions with appropriate evidence and matching policy, role and evaluation time may enable an anchor. Intermediates are path candidates. Enforce applicable key usage, EKU, certificate policy, basic constraints, path length and name constraints. Unknown or unsupported required constraints fail closed. Revocation and trusted historical signing time require separate evidence; a claimed document timestamp is insufficient.

Keep all decision history, record time and effective intervals. Suspension/distrust does not delete certificates. Historical audit must be distinct from current trust. No system roots fallback.

## Experimental local evaluator (v0.1)

Four empty CN built-ins: document-signing, electronic-seal-signing, seal-maker, timestamping. Local JSON document contains policy, reviews, decisions (see schemas/policy-document.schema.json). No write/approval CLI; changes require PR and independent evidence review. Inventory provenance observations remain immutable CANDIDATE records; review events separately reference their SHA-256 IDs. A review can verify or reject the source assertion. Later review events supersede earlier ones; an approval explicitly refers to the exact current verified review ID, and a changed/rejected review requires a new decision. Review references are local assertions, not authenticated identities.

A policy lists eligible anchor fingerprints and intermediate candidates; membership alone does not grant authorization. A TRUSTED decision must match policy ID and version, role, certificate and reviewed source evidence. Positive decisions cannot take effect before recordedAt. Negative decisions may be retroactive. All times are UTC. Evaluation requires explicit evaluation time and knowledge cutoff (not earlier than evaluation). The latest effective known event wins; ties are invalid. Expiration is exclusive and does not resurrect an older decision. A later recorded retroactive denial can change retrospective results. Source-review status is checked at the knowledge cutoff, not inferred from certificate time. Policy version selection is explicit; no cross-policy or cross-version inheritance.

Local reports always have mode UNAUTHENTICATED_LOCAL_POLICY, releaseAuthenticated=false and trustStatus=NOT_ESTABLISHED. LocallyAuthorizedAnchors are policy assertions for review, not usable production trust material. Intermediate candidates are not authorized anchors. No validity/revocation/path/EKU/name-constraint evaluation, no verification of reviewer identity or evidence authenticity, no authenticated history completeness. No signed snapshot. Git/PR review must preserve prior decisions across revisions; the evaluator cannot detect deletion of history across different input documents. No real anchors in built-ins. Production consumers must not use this output as trusted roots.

The loader rejects duplicate/unknown/missing JSON keys, trailing bytes and excessive size/depth. Semantic validation checks inventory links, role separation, exact scope, timestamps and evidence. Embedded Draft 2020-12 Schema validation is applied to input JSON and typed SDK documents. External references are denied; semantic references and time checks remain mandatory.
