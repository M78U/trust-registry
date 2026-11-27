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


## Stage 3: bounded explicit incremental run

From the current source build, execute one selected pass (not available in the previously released Homebrew binary):

```sh
/tmp/trust-registry-monitor sources monitor-run --store monitor-store \
  --interval 168h --max-fetches 2 \
  --id sheca-repository --id sheca-auxiliary --id cfca-repository
```

All IDs and budget are validated before any request or stream creation. IDs are explicit and unique; order is the caller's priority. Only HTTPS_RESPONSE streams are considered; a local observation never refreshes online age. The coordinator takes the existing per-stream writer lock before reading the current validated index/latest, rechecks due time against the live local clock, and keeps that lock across the bounded fetch and append. Fresh, busy, future, corrupt or full streams do not fetch. At most the selected number of application-level GET attempts (including failed attempts), with a five-minute overall context and the existing 30s request timeout. A budget-exhausted row is read-only. Different streams are independent; this is not a cross-source transaction. No retry within a run.

Captures are replayed and indexed using their locally computed digest, explicitly labeled LOCAL_CAPTURE_DIGEST_NOT_INDEPENDENTLY_REVIEWED; do not present this as independent pin approval. The prior independently pinned manual-add path remains available. BASELINE_CAPTURED, BODY_UNCHANGED and BODY_CHANGED_REVIEW_REQUIRED describe only original page bytes. Fetch failure, cancellation, lock or storage failure produces an INCOMPLETE report and nonzero exit, without renewing the previous successful observation; successful rows remain committed. A storage failure can leave an unindexed original, and cancellation after commit cannot undo writes. The report contains digests, not page contents. Retain it privately and inspect per-source statuses. FETCH_BUDGET_REACHED is a normal bounded partial pass, not a claim that every source was checked. Missing/failed sources stay due on later explicit runs; no persistent retry cooldown yet, so do not attach a high-frequency scheduler. Fixed URL/transport constraints, index rollback limits and real source verification limitations remain unchanged.

No changes to CA inventory, policy, publisher, cloud operations or dependency graph. Synthetic transport regressions cover budget, invalid IDs, no repeat fetch when fresh, lock across request, failure preserving baseline, later change and cancellation. Native Go 1.26 acceptance and actual official site behavior are still unverified for this revision.


## Stage 4: persisted attempt cooldown

The stage 3 command now reserves one attempt before any GET, under the same per-source HTTPS stream lock. A small canonical attempt.json (max 4 KiB) is atomically replaced; originals and history index are unchanged. No new flags or scheduler. The local retry interval doubles for consecutive unresolved attempts: 1h, 2h, 4h, 8h, 16h, then capped at 24h. Cooldown is measured from attempt start, not finish. At the exact retry boundary the source is eligible only if its observation is also due and budget allows. A failed request consumes a fetch attempt; no retry within a run.

ATTEMPT_UNCONFIRMED is written before a request, so a crash or cancellation can consume a cooldown even if no request reached the network. Failures update that same record to SOURCE_FETCH_FAILED, CANCELLED or STORE_WRITE_FAILED. If outcome update fails, the pre-request reservation remains. A failure to reserve blocks the request. A newer indexed successful HTTPS observation (strictly later than attempt start and distinct from the prior baseline) supersedes the attempt and resets the next streak without another success write. Manual newer HTTPS observations can also supersede it; local-input observations never do. No persistent raw error text. The record describes only local scheduling, not a signed source receipt, complete attempt history or authenticated rollback protection. Deleting or rolling back the record can lose cooldown state; protect and back up the store.

monitor-plan and monitor-run both return RETRY_COOLDOWN_ACTIVE with the attempt and next eligible time; the run reports COMPLETED_WITH_COOLDOWN when skips are the only additional condition, and does not consume request budget for them. A corrupt or future attempt or missing known baseline blocks the source with LOCAL_STATE_REVIEW_REQUIRED. No directory scans. Reading a plan adds at most one 4 KiB attempt file per HTTPS stream. No extra network requests, dependencies or cloud operations. Operator must still choose a reasonable scheduling cadence; the direct monitor-fetch research command is not governed by the coordinator cooldown. No Retry-After parsing or global per-host rate limit in this stage. No automatic trust changes.

Synthetic regressions cover persisted failures, no repeat GET, exact boundary, capped backoff, crash reservation, corrupt state and successful supersession. Full native Go 1.26 tests not run in implementation environment.


## Stage 5: SHECA structured table adapter (experimental)

Public indexed and rendered research of https://www.sheca.com/repository on 2026-11-27 shows separate root, intermediate and disuse tables with bilingual name, SHA-1, validity and link headings. Repeated published SHA-1 claims and same-name rows occur. Raw HTML could not be fetched in the implementation environment (DNS failure); the real DOM/layout and live response are NOT validated. Do not interpret this as a verified complete listing. The adapter is a separate local Python 3 standard-library tool (no change to Go locks, CLI build, or Homebrew dependencies). Its synthetic fixtures are original invented rows, not copied CA site HTML. Python 3.11+ recommended.

From the current repository root, obtain a private pinned observation using the existing monitor-fetch or monitor-local command, or select the exact original JSON from the private monitor-store. Retain its receipt digest separately. Then:

```sh
python3 -B -m unittest discover -s scripts -p test_sheca_source_adapter.py -v
umask 077
python3 -B scripts/sheca_source_adapter.py \
  --sha256 INDEPENDENT_OBSERVATION_PIN /path/to/private-observation.json \
  > /path/to/private-sheca-projection.json
```

Use a new private output path. The script independently checks supplied whole-file SHA-256, unique JSON keys, exact source metadata, mode, UTC time, body length/hash and base64. It is not Go canonical replay, signature verification or independent authentication; use the existing Go verifier for canonical archive replay. UTF-8 only, max 3 MiB observation, 2 MiB original body, 2048 total rows, bounded cell text/link sizes. HTMLParser is a limited tokenizer, not a browser DOM or JS execution environment. The strict profile requires all three nonempty sections with matching four-column headers and explicit row/cell closures. Unknown, partial or unsupported formats stop with nonzero exit and no projection; do not treat a failed parse as an empty catalog. No JavaScript execution, external requests, or link following. Observed href strings are **untrusted literal claims**, not validated URLs or authorized endpoints; never execute them or render them as active HTML. Normalizes English dates, compact/colon SHA-1 spelling, whitespace and edge directional marks on fingerprint; sorts deterministic row projections, collapses exact duplicates only, flags repeated distinct SHA-1 claims. Section DISUSE is a page label only, not cryptographically established revocation or CA role. SHA-1 is not certificate identity or authority; new certs require exact DER SHA-256 and reviewed independent provenance. All output remains private and EXTRACTED_REVIEW_REQUIRED. No trust, membership, completeness or redistribution conclusion.

The current synthetic tests passed using Python standard library in the implementation environment (4 test methods). No native Go locked run or real HTML acceptance. Before building semantic comparison or unattended parsing, capture the real page and check all extracted rows, headings and hrefs against a human-readable view. If actual markup differs, adapt a reviewed fixture with permission, not a permissive fallback. Later adapters may be separately staged. No new network, cloud or Go dependency. Existing observation/cooldown history remains unchanged.


## Stage 6: semantic comparison of SHECA listing claims

Experimental offline comparison, using the same stage 5 adapter on two independently pinned original observations, not editable projection JSON. This is intentionally separate from the online coordinator until the real page profile is accepted. Both captures must have the same observation mode and strictly increasing UTC time (up to nanosecond precision). A failed parse, wrong pin or wrong source stops the whole comparison; no empty-catalog substitution.

```sh
python3 -B -m unittest discover -s scripts -p 'test_sheca_source_*.py' -v
umask 077
python3 -B scripts/sheca_source_diff.py \
  --previous-sha256 FIRST_PIN --current-sha256 NEXT_PIN \
  /path/to/private-first.json /path/to/private-next.json \
  > /path/to/private-sheca-diff.json
```

Use a fresh private output path and check the exit status before consuming it. Both observation pins must be retained independently. The report groups rows by normalized published SHA-1 claim, not certificate identity, retains all distinct rows per group, and emits deterministic before/after changes. New or absent groups are NEW_PUBLISHED_FINGERPRINT_CLAIM or PUBLISHED_FINGERPRINT_NOT_OBSERVED, never CA creation/revocation. When both groups have exactly one row, report changed section, label, published validity date, link text and/or literal hrefs. When either has multiple distinct rows, report AMBIGUOUS_FINGERPRINT_GROUP_CHANGED without inventing a pairing. All ambiguous groups remain review signals, even when unchanged. Same-name different SHA-1 is not automatic renewal, replacement or identity matching.

An aggregate exact-duplicate count change is a review signal even if unique rows are unchanged. Duplicate multiplicity is not tracked per fingerprint by the current adapter, so equal aggregate counts do not prove equal multiplicities. BODY_CHANGED_PROJECTED_ROWS_UNCHANGED means only that the recognized normalized unique rows and aggregate duplicate count matched; it is not proof that the page only changed layout, or that no certificate or policy changed. Unrecognized page text, policies, JS content, and other nonprojected content are outside semantic coverage. The raw observations remain available for review. No network, writes by the script itself, certificate acquisition, inventory mutation, trust changes, cloud operations or Go dependency changes. Keep output private; hrefs remain untrusted literals.

Added six synthetic comparison tests for format-only changes, new/missing claims, field/section changes, ambiguity/duplicate counts, determinism, pin/time/mode and invalid-page rejection. Test execution and live page profile acceptance remain pending for this revision; the implementation environment cannot resolve raw.githubusercontent.com to retrieve the exact test checkout. Next: actual SHECA HTML validation and review queue integration with source-level change reports; do not schedule automated semantic conclusions before real-page acceptance.


## Stage 7: actual SHECA page acceptance (operator checkpoint)

The stage 5/6 adapters remain experimental. The implementation container still cannot resolve the real SHECA host or raw.githubusercontent.com; no actual page bytes or native Go 1.26 validation have been obtained here. The new acceptance script reprojects one exact independently pinned original and cross-checks the existing selected 17 research rows in pkg/sources/sheca.json (not an authoritative or exhaustive baseline). It reports exact selected field matches, missing SHA-1 claims, mismatched fields, ambiguous SHA-1 groups, section counts and unlisted claims. DISUSE is compared only as a section; role is not inferred from it. The baseline file SHA-256 binds the report to the actual local baseline. The report excludes raw page contents and literal hrefs; row names/dates/fingerprints remain unverified source claims and should still be reviewed before sharing. All results remain HUMAN_REVIEW_REQUIRED and liveProfileAccepted=false, even if all selected rows match. No catalog edit, certificate import, URL follow, revocation or trust decision.

From a clean checkout of the current main after merge, on a trusted Mac:

```sh
git switch main
git pull --ff-only
export PATH="$(brew --prefix go@1.26)/bin:$PATH"
python3 -B -m unittest discover -s scripts -p 'test_sheca_source_*.py' -v
go build -mod=readonly -o /tmp/trust-registry-monitor ./cmd/trust-registry
umask 077
work="$(mktemp -d "$HOME/trust-sheca-acceptance.XXXXXXXX")"
/tmp/trust-registry-monitor sources monitor-fetch --id sheca-repository --out "$work/observation.json" > "$work/receipt.json"
cat "$work/receipt.json"
```

Inspect the receipt and independently retain its observationSHA256. If the direct HTTPS request fails, manually save the actual page HTML from the independently checked official page and use monitor-local with explicit UTC observation time and a fresh output path; do not substitute search snippets, a screenshot, or rendered plain text. Do not mix modes in later comparisons. Run these only after the capture succeeds, replacing the placeholder with the reviewed receipt digest:

```sh
pin='REVIEWED_OBSERVATION_SHA256'
python3 -B scripts/sheca_source_acceptance.py --sha256 "$pin" "$work/observation.json" > "$work/acceptance.json"
jq '{status,counts,sectionRowCounts,projectedDistinctRows,exactDuplicateRows,unlistedFingerprintClaimCount,liveProfileAccepted}' "$work/acceptance.json"
python3 -B scripts/sheca_source_adapter.py --sha256 "$pin" "$work/observation.json" > "$work/projection.json"
```

Check exit codes before reading outputs; parse errors produce no successful report. Compare all sections, actual table rows, href literals and any ignored or dynamically rendered content against the independently inspected page. A selected-row match does not prove complete extraction. If the parser rejects the real markup, preserve the private observation and report the exact error; do not relax checks or treat the page as empty. No raw HTML or private paths in Git. Send the reduced jq summary and parser error if any; share the actual capture only if reviewed for secrets/private data and permitted. No automatic semantic scheduling until real profile acceptance. The four added synthetic acceptance tests are not executed in the implementation environment; run the full Python suite above. No Go dependency, CI, Cloudflare or release changes.


## Stage 8: private maintenance review batches

An explicit offline queue preparation tool replays two independently pinned original SHECA observations through stage 6. It never consumes editable diff JSON. Every changed fingerprint group becomes a pending review task, unchanged ambiguous groups also become tasks, and exact duplicate count changes are retained. Every raw body change creates a separate source-body review task, even if projected rows match, because material outside the parser coverage can change. Failed parsing, invalid pins, mixed mode or non-increasing time block the entire batch rather than generating an empty review queue.

From the repository root with the two original observations and separately retained pins:

```sh
umask 077
mkdir -m 700 "$HOME/trust-maintainer-queue"
python3 -B scripts/sheca_source_review_queue.py prepare \
  --queue "$HOME/trust-maintainer-queue" \
  --previous-sha256 FIRST_PIN --current-sha256 NEXT_PIN \
  /path/to/private-first.json /path/to/private-next.json
```

Inspect the resulting receipt and retain batchSHA256 independently. The file named <batchId>.json in the queue directory contains deterministic tasks and a canonical diff digest, without raw HTML, hrefs or row labels. Inspect it locally with jq. Task IDs bind batch ID, task kind and optional published SHA-1 claim. The batch ID binds source, adapter and exact observation pair, so repeated identical input is idempotent. A new observation pair is a separate review batch, not a claim of global incident deduplication. The immutable-by-convention canonical file is written via a synced private temporary file and no-replace hard link; conflicting existing data is rejected, not repaired. Max batch size 8 MiB. No directory scan, directory fsync, signed ledger or hostile-filesystem rollback protection. Use an existing private directory outside Git, retain pins and backups.

To verify the exact saved batch, rerun with the same originals and pins:

```sh
python3 -B scripts/sheca_source_review_queue.py verify \
  --queue "$HOME/trust-maintainer-queue" --batch-sha256 REVIEWED_BATCH_PIN \
  --previous-sha256 FIRST_PIN --current-sha256 NEXT_PIN \
  /path/to/private-first.json /path/to/private-next.json
```

Verify checks exact replay and independent batch digest. All tasks are PENDING_HUMAN_REVIEW; this stage has no disposition/closure API or global queue index. NO_TASKS_FROM_THIS_COMPARISON is not proof of no source change or current trust. The live adapter profile is still unaccepted; do not automate semantic conclusions or publish evidence. No acquisition, inventory mutation, review signature, trust grant, scheduler, dependency or Cloudflare changes. Four synthetic test methods added (not executed in the implementation environment). Next stage: append-only human review dispositions and bounded pending task index; the real SHECA capture checkpoint remains open.


## Stage 9: append-only source-review dispositions

After preparing and independently pinning a batch, select one exact task ID. Both commands below replay the original observation pair and verify the saved batch against its independent pin; no editable projection or batch alone is accepted.

```sh
python3 -B scripts/sheca_source_review_disposition.py history \
  --queue "$HOME/trust-maintainer-queue" --batch-sha256 BATCH_PIN \
  --task-id TASK_ID --previous-sha256 FIRST_PIN --current-sha256 NEXT_PIN \
  /path/to/private-first.json /path/to/private-next.json

python3 -B scripts/sheca_source_review_disposition.py record \
  --queue "$HOME/trust-maintainer-queue" --batch-sha256 BATCH_PIN \
  --task-id TASK_ID --previous-sha256 FIRST_PIN --current-sha256 NEXT_PIN \
  --expected-head EMPTY --action NEEDS_INVESTIGATION \
  --at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --reviewer 'local-maintainer' --note 'Check independent source evidence' \
  /path/to/private-first.json /path/to/private-next.json
```

Replace all placeholders with the separately retained pins and task ID. EMPTY explicitly means no prior disposition. For subsequent actions retain and use the last returned headSHA256 (not a blindly refreshed value). NEEDS_INVESTIGATION and REVIEW_COMPLETE are permitted from pending/investigation; REOPENED is permitted only after REVIEW_COMPLETE and returns to pending. The UTC recorded time must strictly exceed current observation time and prior event time. Reviewer and note are bounded printable assertions (128 and 1024 characters); do not put secrets into command arguments or notes. Reviewer identity is not authenticated. REVIEW_COMPLETE means only that the human recorded completion of the source review task, not CA approval, independent reviewer signoff, live profile acceptance, or authorization to publish.

One private task stream under <batchId>.dispositions/<taskId> contains at most 32 numbered immutable-by-convention events, each max 16 KiB. Events bind the exact batch digest, task, sequence, prior event digest, action, resulting status, UTC time and human notes. Replay verifies the chain, allowed transitions and canonical bytes. Reads enumerate only the explicitly selected task's bounded directory, never the global queue. The writer uses a cooperative per-task lock, exact expected head, synced private temp file and no-replace hard link; previous event files are never edited. Conflicts, corrupt records, gaps, unexpected entries and stale heads fail closed. Inspect stale locks manually. A lost response after commit requires a history read; retries with stale heads fail rather than silently repeat. No directory fsync or hostile filesystem protection. A deleted suffix or fully rewritten chain may be undetectable without an independently retained head; protect the private store and back it up. History is advisory and may race a cooperating writer; use expected head on record. No global pending index yet.

Four synthetic test methods added, covering transitions, reopen, stale head, wrong task/batch, corruption/gaps/lock and note bounds. Run the full Python suite from a clean checkout:
```sh
python3 -B -m unittest discover -s scripts -p 'test_sheca_source_*.py' -v
```
Native execution of these new tests and actual SHECA page acceptance remain pending. No dependency, cloud operations, certificate inventory mutation, formal review signatures or trust decisions.


## Stage 10: bounded advisory pending-review index

Refresh one explicitly selected batch from its original pinned observation pair and independent batch pin. This verifies the batch once and replays the selected batch's task histories, not all historical batches. Index storage is a private canonical JSON file with one cooperative writer lock and atomic replacement. Task and batch IDs are deterministic; conflicting pins, corrupt index, backwards refresh time, future disposition relative to refresh time, and loss/rewrite of previously indexed nonempty event heads are refused. No automatic deletion. Limits: 64 batches, 512 tasks per batch, 4096 total tasks, 4 MiB index; at most 32 existing events per task. A batch exceeding these limits remains reviewable using the earlier selected-task tools. No migration or automatic eviction. If capacity is reached, preserve the old store/index and establish a reviewed new workspace.

```sh
python3 -B scripts/sheca_source_review_index.py refresh \
  --queue "$HOME/trust-maintainer-queue" --batch-sha256 BATCH_PIN \
  --previous-sha256 FIRST_PIN --current-sha256 NEXT_PIN \
  --at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  /path/to/private-first.json /path/to/private-next.json

python3 -B scripts/sheca_source_review_index.py list \
  --queue "$HOME/trust-maintainer-queue" --status open --limit 50
```

List reads only the index, no network, writes, directory enumeration or event replay. Default open includes pending and investigation; all and individual statuses are available, with deterministic batch/task ID ordering and offset pagination (max 200 per page). Counts cover explicitly refreshed batches only. An absent index means zero indexed batches, not zero pending work. Each task includes its cached head, status and batch refresh timestamp. Refresh again after any disposition or new batch; stage 8/9 commands do not update this advisory cache automatically. Refresh can race a disposition writer; it is not an atomic snapshot across tasks or batches. Do not authorize a disposition or publication from cached data: use the selected-task history tool and independently retained head. No reviewer notes or original page contents in the index. Local cache is not authenticated, not rollback resistant, and cannot detect a deleted index, omitted batches or concurrent changes after replay; retain independent pins and backups. Stale index locks require operator inspection. No directory fsync.

Added four synthetic test methods for explicit refresh, filters/pagination, multiple batches, repeat, missing prior history, wrong pins, lock and corrupt cache. Test execution and real SHECA profile acceptance remain pending. No Go dependency changes, cloud services, scheduling, inventory modification, or trust authorization. Next: operator-oriented workflow validation and practical maintenance entrypoint before expanding adapters.


## Stage 11: unified maintainer command

Use scripts/trust_maintainer.py as the local operator entrypoint. The underlying tools remain separately callable. The command does not automatically convert network observations into trusted data or even into review batches. Real SHECA DOM acceptance is still open. Python 3.11+ and the current source-built Go CLI are required for online check. No new Python packages or Go modules.

From current main after merge, build and test:

```sh
git switch main
git pull --ff-only
export PATH="$(brew --prefix go@1.26)/bin:$PATH"
python3 -B -m unittest discover -s scripts -p 'test_*.py' -v
go test -mod=readonly ./pkg/sources ./cmd/trust-registry
go build -mod=readonly -o /tmp/trust-registry-monitor ./cmd/trust-registry
python3 -B scripts/trust_maintainer.py --help
```

Use existing private directories outside the repo, or create fresh ones:

```sh
umask 077
mkdir -m 700 "$HOME/trust-monitor-store" "$HOME/trust-maintainer-queue"
python3 -B scripts/trust_maintainer.py check \
  --binary /tmp/trust-registry-monitor --store "$HOME/trust-monitor-store" \
  --interval 168h --max-fetches 1 --id sheca-repository
```

Check delegates to the explicitly selected trusted absolute executable without shell or arbitrary extra arguments, preserves stdout/stderr and exit code, and sets a 360s outer subprocess timeout. Go retains its allowlist, budget, cooldown and per-stream locking; no automatic retry. Only use a binary you trust. An outer timeout may leave local reservations or stale locks; inspect before retry. No automatic reading of output or promotion of locally captured pins.

After two successful comparable observations, independently retain and inspect both exact observation digests. Select their original JSON files in the store (or externally saved originals). Use acceptance on a single real capture to obtain the stage 7 baseline cross-check. Then preview tasks with no writes:

```sh
python3 -B scripts/trust_maintainer.py acceptance --sha256 NEXT_PIN /path/to/private-next.json

python3 -B scripts/trust_maintainer.py plan \
  --previous-sha256 FIRST_PIN --current-sha256 NEXT_PIN \
  /path/to/private-first.json /path/to/private-next.json
```

Review the preview and retain its batchSHA256 separately. Enqueue requires that exact reviewed batch pin, reprojects both observations, persists the immutable batch and refreshes only that batch's index:

```sh
python3 -B scripts/trust_maintainer.py enqueue \
  --queue "$HOME/trust-maintainer-queue" --batch-sha256 BATCH_PIN \
  --previous-sha256 FIRST_PIN --current-sha256 NEXT_PIN \
  --at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  /path/to/private-first.json /path/to/private-next.json

python3 -B scripts/trust_maintainer.py status \
  --queue "$HOME/trust-maintainer-queue" --status open
```

Use history and record with the same pair/pins/task fields as stage 9. Record automatically attempts a single-batch index refresh after the event commit; it requires the explicit independently retained expected head. No unattended actions or review identity authentication. Enqueue and record have separate durable write and advisory-index commit boundaries: WRITE_COMMITTED_INDEX_REFRESH_FAILED with exit 1 means the batch or event already committed (receipt included), and the index may be stale. Do not repeat a disposition to fix the cache; inspect the committed state and run refresh with the same pair/pins and a valid newer --at. Other failures do not guarantee no writes (I/O failure or interrupted process); inspect exact history and receipts. The status query is still advisory, bounded and may omit unindexed batches; no directory scan or automatic trust. Private output and human notes must remain local. No cloud resource or release change. Added four synthetic integration test methods; not executed in the implementation container (GitHub DNS unavailable and Go 1.23.2 only). Run the above local tests and complete stage 7 before unattended maintenance or a new preview release.


## Stage 12: private maintainer workspace

Create a new workspace outside the checkout, with fixed observations/ and review-queue/ directories and a small private canonical workspace.json. No automatic default paths, adoption of existing directories, network or scheduler during initialization. Explicit trusted Go executable (regular file, owner-executable, not group/world writable or symlink; maximum 128 MiB) and independently inspected SHA-256, ordered fixed source IDs, whole-hour check interval 1–720h, and request budget are required. Both the config and child directories are validated before use. No source URLs, shell commands, credentials, pins for source observations, or reviewer identities in config.

On macOS, from the repository after merge, build a fresh binary at an explicitly chosen stable private path (create a private bin directory first if needed; do not replace an existing bound binary):

```sh
umask 077
mkdir -m 700 "$HOME/trust-maintainer-bin"
go build -mod=readonly -o "$HOME/trust-maintainer-bin/trust-registry" ./cmd/trust-registry
shasum -a 256 "$HOME/trust-maintainer-bin/trust-registry"
```

Inspect and retain the expected executable digest. Use a new workspace path and replace CLI_PIN:

```sh
python3 -B scripts/trust_maintainer.py --workspace "$HOME/trust-maintainer" workspace-init \
  --binary "$HOME/trust-maintainer-bin/trust-registry" --binary-sha256 CLI_PIN \
  --interval-hours 168 --max-fetches 1 --id sheca-repository

python3 -B scripts/trust_maintainer.py --workspace "$HOME/trust-maintainer" workspace-info
python3 -B scripts/trust_maintainer.py --workspace "$HOME/trust-maintainer" check
python3 -B scripts/trust_maintainer.py --workspace "$HOME/trust-maintainer" status
```

Workspace mode supplies check parameters and queue directory for enqueue/refresh/history/record/status; direct conflicting options are refused. Offline acceptance and plan still take explicit originals and pins without workspace. Direct commands from stage 11 remain supported. Check rehashes the bounded binary before delegation. This is a local consistency check, not code signing or protection against malicious filesystem replacement between check and execution. Use trusted private parents and filesystem; config digest is informational and should be retained independently. Info does not verify binary bytes. A changed binary is blocked; no rebind/edit/migration command in this stage. Preserve old config and evidence; explicit reviewed rebind and configuration update are future work. Interrupted init can leave a partial directory; inspect it, never blindly overwrite it. No directory fsync. No automatic collection-to-semantic conversion, profile acceptance, trust decision, cloud resources or dependency changes. Four synthetic test methods added; current environment cannot clone GitHub (DNS) and has Go 1.23.2 only, so actual checkout tests and real page acceptance are pending.
