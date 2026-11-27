# Reviewed TUF publication staging gate (experimental)

The isolated TUF publisher has a new build-reviewed mode. It rechecks the complete signed review dossier, artifact hashes, pinned authority, distinct release approvals and current approval window before building TUF metadata. Independently pin initial TUF root and authority configuration. All four root roles must use unique Ed25519 raw keys, no aliases, duplicate IDs, unused root keys or reuse of any reviewer/approver key. This is checked even for root role keys not used in this build. Standard publisher still verifies role signatures, metadata version and expiry ordering.

First sequence requires explicit --bootstrap, sequence 1, no previous snapshot or pin, and no positive authorization decision in initial policies. Subsequent build-reviewed requires exact previous accepted envelope plus independently trusted SHA-256. Compare both validated envelopes regardless of previous expiry (historical inspection only). Require sequence exactly previous+1 and strictly increasing creation time; preserve all previous nonpolicy inventory files byte-for-byte (including source observations), append new observations only with recording time after previous creation. All old policy versions and event prefixes preserved, new policy versions start without positive authorizations and all new review/decision records after prior creation. No deletion or mutation of historical inventory; capacity limits will require separate reviewed archival design. This is intentionally conservative. A caller must supply actual accepted head, not merely an arbitrary valid snapshot. No persistent ledger, lock, authenticated baseline retrieval or resistance to stale pin selection. Bootstrap does not prove no prior publication.

```sh
tuf-publish build-reviewed \\
  --root root.json --root-sha256 INDEPENDENT_ROOT_PIN \\
  --version 1 --now CURRENT_RFC3339 \\
  --targets-expires TARGET_EXPIRY --snapshot-expires SNAPSHOT_EXPIRY \\
  --timestamp-expires TIMESTAMP_EXPIRY \\
  --targets-key TARGETS.pem --snapshot-key SNAPSHOT.pem --timestamp-key TIMESTAMP.pem \\
  --dossier review-dossier.json --evidence PRIVATE_EVIDENCE \\
  --authority authority.json --authority-sha256 INDEPENDENT_AUTHORITY_PIN \\
  --approval final-approval.json --bootstrap --out staging-v1 candidate.json
```

For later sequences replace --bootstrap with --previous prior.json --previous-sha256 INDEPENDENT_PREVIOUS_PIN and change version. Use exact actual time. Approval signatures bind the snapshot and dossier, not the TUF root or chosen metadata expiries; root and metadata parameters require independent operator review. Approval time bounds staging creation, not metadata lifetime; metadata cannot exceed snapshot expiry. Outputs exactly the same five TUF files as research mode, in a fresh private staging directory; local JSON report contains approval/transition details, not a public target. Never publish dossier or evidence. No network, upload or release tag. An interrupted write may leave partial staging; discard and rebuild under operator control. Do not serve research mode output or permit bypass: build remains explicitly local research, and software cannot stop key holders from signing outside the gated mode. Use separate key custody and enforced release pipeline. Neither mode grants production trust; releaseAuthenticated false, trustStatus NOT_ESTABLISHED. Client does not independently verify approval. Persistent publisher ledger, signed authorization bound to release root/metadata, root rotation, client-side enforcement, dependency lock and full tests remain required before production.

Synthetic tests cover missing approvals, first sequence, baseline omission, same/skipped sequence, omitted/replaced policy, approval expiry and reused raw keys. Go tests not executed; automatic CI disabled. No real keys or CA bytes produced.
