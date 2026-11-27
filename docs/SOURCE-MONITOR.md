# Source monitoring: private observations (stage 1)

This is the first maintainer feature, not a scheduled service or a trust-store updater. Eight fixed research URLs from the existing CA/SATL catalog can be explicitly observed. There are no user-defined URLs, HTML link traversal, browser rendering, automatic retries, catalog modifications, CA import, trust changes, Cloudflare APIs, D1/KV writes or scheduled jobs.

Run from current source (the released Homebrew binary does not yet include these commands):

```sh
go build -mod=readonly -o /tmp/trust-registry-monitor ./cmd/trust-registry
umask 077
mkdir -m 700 "$HOME/trust-monitor-private"
cd "$HOME/trust-monitor-private"
/tmp/trust-registry-monitor sources monitor-list
/tmp/trust-registry-monitor sources monitor-fetch --id sheca-repository --out sheca-first.json
# At a later time, explicitly observe the same source into a new file.
/tmp/trust-registry-monitor sources monitor-fetch --id sheca-repository --out sheca-next.json
/tmp/trust-registry-monitor sources monitor-diff --previous-sha256 FIRST_PIN --current-sha256 NEXT_PIN sheca-first.json sheca-next.json
```

Retain the two observationSHA256 values from the receipts independently, not just from the files being compared. Exact canonical JSON (including LF), raw page bytes, SHA-256, length, source ID/URL/kind, observation mode and UTC time are retained. Private output files must not exist. Compare is offline, revalidates both pins and canonical encoding, and requires the same fixed source and mode with strictly increasing recorded time. BODY_CHANGED_REVIEW_REQUIRED is a human review lead; BODY_UNCHANGED means equal captured body bytes only. No HTML parsing, membership inference, semantic diff, verified source identity or authenticated timestamp. Pages can be dynamic, blocked, partial or JavaScript-only. A 200 response can be a challenge page. A failed request is not a removal, and does not produce a successful observation. Existing allowlist changes can require old tooling to reproduce historical observations. Use private storage and retention/backup policy, never publish raw page bodies by default.

The explicit HTTPS observation uses existing research transport: ordinary platform TLS, no configured proxy, redirects or compression, 30s total request limit, 15s header timeout, 32 KiB header limit, only HTTP 200 and HTML/XHTML/plain text, up to 2 MiB body and 3 MiB observation. No cookies or credentials. Fixed URL restriction is not DNS/IP pinning; run only with trusted DNS/network and do not use this as an arbitrary URL service. No claim of a signed network receipt. Local fallback for manually saved source content (does not claim actual origin):

```sh
/tmp/trust-registry-monitor sources monitor-local --id sheca-repository --recorded-at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --out sheca-local.json saved-page.html
```

Use equivalent capture methods over time; do not compare local and HTTPS modes. Output is an immutable-by-convention private file with no replacement by CLI, not a tamper-proof ledger. Source monitor tests use a synthetic transport and local bytes; actual official site behavior and full Go 1.26 validation remain untested in the implementation environment. Next: bounded recurring scan planning, durable observation index, adapter-specific structured extraction and semantic review queue, then actual owner-approved data changes. No automatic trust.

Homebrew preview #8 was merged and the owner accepted the Bundler test-runner exception. Native direct installed CLI/notice verification remains unreported; source validation passed on the prior exact release. This maintainer change does not create a new software release.


## Stage 2: persistent local observation index and advisory plan

Use an existing 0700 private directory outside the repository. Separate streams per fixed source and capture mode (HTTPS_RESPONSE or LOCAL_INPUT). Each indexed observation retains exact canonical bytes under its SHA-256 name; the small index records at most 512 receipts per stream, with strict chronological order. No directory scans. Keep independent pins and backups. A caller can supply an existing externally obtained observation from stage 1:

```sh
mkdir -m 700 monitor-store
/tmp/trust-registry-monitor sources monitor-add --store monitor-store --sha256 FIRST_PIN sheca-first.json
/tmp/trust-registry-monitor sources monitor-add --store monitor-store --sha256 NEXT_PIN sheca-next.json
/tmp/trust-registry-monitor sources monitor-history --store monitor-store --id sheca-repository
/tmp/trust-registry-monitor sources monitor-verify --store monitor-store --id sheca-repository --sha256 FIRST_PIN
/tmp/trust-registry-monitor sources monitor-plan --store monitor-store --at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --interval 168h
```

Replace FIRST_PIN/NEXT_PIN with independently retained observation SHA-256 receipts. For local captures explicitly choose --mode LOCAL_INPUT when reading/planning/verifying. Add derives mode from verified record. Add is offline: exact pin and canonical replay before writes, cooperative per-stream lock, immutable no-replace original first and atomic index replacement second. Exact replay of an indexed observation is idempotent, new backdated observations rejected. A crash between original and index commit can leave an unindexed file; exact retry reuses it without scanning. Inspect stale locks manually. No auto deletion/repair, no directory fsync, no defense against malicious local filesystem changes. Index is not authenticated or rollback-resistant: missing index is treated as empty, a deleted/rolled-back index cannot be detected without external evidence, and unindexed files are not enumerated. Keep separate independent pins and protect/backup root. 512 entries per source/mode; capacity reached requires operator review/new store, not eviction.

History and planner read at most one bounded 1 MiB index and one latest 3 MiB original per stream; older indexed receipts are unverified assertions unless explicitly verified. Planner covers the eight fixed sources in one selected mode, no writes, no network. Explicit interval 1h–30d (whole seconds), explicit UTC evaluation time. FIRST_OBSERVATION_REQUIRED, OBSERVATION_DUE, NOT_DUE_UNDER_LOCAL_POLICY or LOCAL_STATE_REVIEW_REQUIRED (including future timestamps, corrupt latest, full history). No automatic fetching, failure retry, authoritative freshness or trust. Successful insertion reports raw-body change signal for consecutive observations; no CA membership inference. Scheduling, fetch+store coordinator, structured parsing and notification are subsequent work. No new dependencies or cloud services. Synthetic tests added; full locked validation not yet run on this revision.
