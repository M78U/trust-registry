# Trust policy

Discovery != provenance verification != scoped trust. Candidate data cannot authorize an anchor.

Provenance states: CANDIDATE, PROVENANCE_VERIFIED, REVIEW_REJECTED.
Decision states: TRUSTED, SUSPENDED, DISTRUSTED; no decision means unestablished trust.

Initial purposes: document-signing, electronic-seal-signing, seal-maker, timestamping. Later: code-signing, device-authentication, client-authentication, server-authentication. No inheritance from TLS or cross-purpose escalation. CA path validity is not leaf authorization.

Default anchor lists are empty. Only explicit reviewed decisions with appropriate evidence and matching policy, role and evaluation time may enable an anchor. Intermediates are path candidates. Enforce applicable key usage, EKU, certificate policy, basic constraints, path length and name constraints. Unknown or unsupported required constraints fail closed. Revocation and trusted historical signing time require separate evidence; a claimed document timestamp is insufficient.

Keep all decision history, record time and effective intervals. Suspension/distrust does not delete certificates. Historical audit must be distinct from current trust. No system roots fallback.
