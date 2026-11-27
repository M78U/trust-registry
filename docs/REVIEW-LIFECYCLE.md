# Private evidence review lifecycle

Workspace now accepts up to four explicitly selected bundle archives (--bundle-pin PLAN_SHA256=PRIVATE_DIRECTORY, repeatable), in addition to up to 32 SHECA acquisition observations. It verifies exact original bytes, canonical pinned plan, current catalog and all extracted DER members using the same read-only preflight as bundle apply. Only members matched to published fingerprint leads produce provenance candidates; exact complete provenance equality is required to link a snapshot record. No directory path is exported in the workspace report. Missing matches remain informational, never proof of origin or authorization. Per bundle the existing 16 MiB original, 32 members, 1 MiB/member and 512 KiB plan limits apply; extracted DER files are read once per selected archive and checked against original members. No network or cloud storage. Protect private local directories.

Workspace adds progress counters and an ordered reviewQueue. Pending/rejected tasks and asserted approvals with diagnostic findings are listed; asserted approvals with complete referenced byte checks are counted separately, not authenticated. EvidenceComplete means all required slots match bytes and no diagnostic findings, not evidence truth or review approval. Queue is a diagnostic subset, never a release gate; the existing Check and independent signed approval flow remain authoritative. JSON report is the private export, use protected shell permissions and keep outside web assets.

## Reuse references for a new snapshot

Retain independent snapshot hashes and canonical prior dossier hash (dossierSHA256 from workspace). Canonical hash is compact Go struct JSON plus LF, not hash of pretty-printed input. The new snapshot must have a strictly higher sequence and later creation time and be current at supplied evaluation time. Prior snapshot may be expired; both are fully verified for integrity and exact task membership. This is a local reference migration, not validation of an append-only publication transition.

```sh
trust-registry review reuse-evidence --previous old.json \\
  --previous-sha256 OLD_SNAPSHOT_PIN --previous-dossier old-dossier.json \\
  --previous-dossier-sha256 OLD_CANONICAL_DOSSIER_PIN \\
  --snapshot-sha256 NEW_SNAPSHOT_PIN --evidence private-evidence \\
  --at CURRENT_RFC3339 --out new-dossier.json new.json
```

Only exact unchanged Requirement structs can reuse artifacts; policy changes alter the policy digest and invalidate reuse. Rejected tasks do not reuse references, malformed duplicate/unexpected reference sets are skipped, each valid artifact file is rehashed once per invocation within existing workspace budgets. Missing/changed files are not copied into the new dossier. New or altered tasks remain empty. All new tasks are PENDING with empty reviewer, note and reviewedAt; no old decisions, signatures or approvals transferred. Output is a fresh canonical dossier file (no overwrite) and JSON report with reuse counts and next canonical hash. Human review must reassess evidence relevance and validity, then run normal check and approval signing. No network, repeated file copies, Cloudflare bindings or writes; no automatic PR checks. Synthetic tests added, not executed. Real CA collection and locked Go validation still pending.
