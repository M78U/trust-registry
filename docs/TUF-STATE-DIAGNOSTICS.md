# Strict local state diagnostics

Use `tuf-load --diagnose` with the same independently pinned initial root and review authority as the strict consumer:

```sh
go run ./cmd/tuf-load --state STATE --root-sha256 INITIAL_PIN \
  --authority AUTHORITY.json --authority-sha256 AUTHORITY_PIN --diagnose
```

Optional all-or-none checkpoint flags: `--checkpoint-sequence N --checkpoint-snapshot-sha256 HEX --checkpoint-root-version V`. SDK: `DiagnoseState(DiagnosticOptions{...})`. JSON report is advisory, not a consumer session or a release approval. Status and recommendation are fixed codes; paths, raw errors, CA bytes and source URLs are omitted. Digests and sequence numbers identify local evidence. Diagnostic results can become stale immediately.

| Status | Recommended next step |
| --- | --- |
| INSTALLED_EVIDENCE_MATCHES | Open the normal strict consumer, which revalidates current state. |
| ROOT_CACHE_BEHIND_ARCHIVE | Review exact archived head, then explicitly recover root cache; subsequently refresh/install online with checkpoint. |
| PENDING_RECOVERY_CANDIDATE / PENDING_COMMITTED_CLEANUP | Explicitly recover pending installation, which rechecks everything before writing. |
| INSTALLED_EXPIRED / PENDING_EXPIRED | Verify a forward online refresh with retained checkpoint. |
| INSTALLED_CACHE_MISMATCH / PENDING_CACHE_MISMATCH / METADATA_INCOMPLETE / NO_INSTALLED_EVIDENCE | Inspect state and verify a forward refresh; no deletion or rollback. |
| INSTALLED_BELOW_CHECKPOINT / PENDING_BELOW_CHECKPOINT | Forward update with the independent checkpoint; do not use old evidence. |
| STATE_LOCKED | Check active writer; no automatic lock breaking. |
| STATE_MISSING | Investigate before explicit bootstrap using independent pins and checkpoint. |
| Other invalid/conflict statuses | Inspect protected state or independent pins; do not force recovery. |

The diagnostic takes and removes only the existing cooperative lock; no persistent state writes, recovery, automatic refresh, network or cloud service operation. It checks canonical configuration, bounded numbered archive and exact cached root, verifies root chain and role separation, and reads only the latest installed record and at most one pending journal. For evidence, historical verification at recorded acceptance establishes the signed validity window; expiry is evaluated at diagnostic time. Cache equality and checkpoint matching are reported separately. `checkpointProvided: false` means no independent external rollback checkpoint was supplied; matching then only means no such constraint was requested.

The earliest metadata/application expiration is reported. Missing or corrupt files, forks, clock earlier than recorded acceptance, conflicting installation history and invalid signatures fail closed. A valid candidate is not a guarantee that repair can succeed later; strict recovery and loading revalidate under their own locks. Unchecked later stages may be omitted when an earlier problem blocks diagnosis. Lock presence cannot distinguish a live writer from a stale lock. No diagnosis of remote freshness, no inspection of every historical record, no tamper-proof storage, no automatic cleanup of staging files, and no production trust determination.

Synthetic integration tests exercise healthy, expired, locked, root-lag, pending, corrupt and post-commit states. They have not been executed; Go 1.26 and dependency lock/manual acceptance remain outstanding.
