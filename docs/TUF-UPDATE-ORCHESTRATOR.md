# Strict Registry update coordinator

The isolated TUF module exposes `CoordinateUpdate(ctx, CoordinateOptions{...})`. It combines existing strict local diagnosis, explicitly authorized recovery or refresh, and reopening the installed consumer. It does not create state, replace the independent pins, schedule work or implicitly switch actions. The zero SDK mode is plan-only.

CLI example (run from tools/tuf-client):

```sh
go run ./cmd/tuf-load --state STATE --root-sha256 INITIAL_PIN \
  --authority AUTHORITY.json --authority-sha256 AUTHORITY_PIN \
  --coordinate plan
```

Use the same independently provisioned state identity and optional all-or-none `--checkpoint-sequence N --checkpoint-snapshot-sha256 HEX --checkpoint-root-version V` flags for subsequent calls. Keep the checkpoint outside mutable client state. Select exactly one mode per call:

| Mode | Authorization and outcome |
| --- | --- |
| plan | Local advisory diagnosis only; no session and no recovery. |
| open | Opens a strict session only for matching installed evidence. |
| recover-root | Only diagnosed root-cache lag, with explicit `--root-head-sha256 EXPECTED_HEAD`; no network or session. |
| recover-pending | Only a diagnosed recoverable pending installation or committed cleanup; revalidates, commits/cleans and opens the strict session. |
| refresh | Explicit HTTPS `--metadata-url URL --targets-url URL`; only healthy state or a forward-refresh recommendation, performs one existing bounded strict refresh/install and opens the session. |

Missing state requires a separate explicit bootstrap. Corrupt/conflicting state and a busy lock block execution. Root recovery never implicitly refreshes; the next call must explicitly authorize it. Pending recovery operates on the currently verified eligible journal, not a previously approved plan digest. Every underlying operation rechecks the state under its own cooperative lock. The report's diagnostic is the pre-action observation, not a post-action assertion.

The JSON result includes mode, status, diagnostic, actionAttempted/actionCompleted, completed install or root recovery result when available, and on CONSUMER_READY the consumer info and exact newly checked checkpoint. SDK also returns the live detached session; CLI reports its info only. Callers persist checkpoints independently after success. Session reopening checks the exact sequence, digest and root version of the actual action result (or diagnosed installed release for open), and independently reapplies the supplied checkpoint. A concurrent change between stages cannot silently substitute another release. No session is returned on failure or cancellation.

This is not an atomic multi-step transaction. A completed action can remain committed even if reopening the session fails or cancellation arrives afterward. An action error may also leave advanced metadata or pending evidence; inspect again, never infer rollback from failure. Cancellation is checked between stages and passed to the existing online transport; it does not interrupt local cryptographic operations or reverse writes already started. No retries or fallback. CLI emits the structured result even when the SDK reports an error and exits nonzero. No new HTTP calls beyond one explicitly selected existing refresh, no new Cloudflare binding, and no CA or document trust grant.

Synthetic integration coverage uses local TLS and counts requests to demonstrate offline modes do not invoke transport, explicit refresh does, and inappropriate action/cancellation are refused. Go execution and locked dependency acceptance remain pending.
