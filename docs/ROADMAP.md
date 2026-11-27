# Roadmap

- [ ] Phase 0 — Bootstrap, architecture, governance, threat model, license, PR/CI settings (#2).
- [ ] v0.1 — Inventory, bounded DER/PEM and SM2 parsing, SHA-256, provenance, schemas, trust policy and decisions, indexes, CLI, SDK, validation and synthetic tests (#3, #4). No unauthorized trust decisions.
- [ ] v0.2 — SHECA first, SATL, CFCA, BJCA, GDCA; independently verify official sources, redistribution, certificate relations, usage and historical evidence (#5). Candidates only unless approved.
- [ ] v0.3 — Secure snapshot generation, authenticated distribution, rotation, expiration, rollback protection and SigLens integration (#6). No production defaults before this gate.
- [ ] v0.4 — Read-only Cloudflare Workers Explorer, public browsing, relations, evidence and snapshots (#7).
- [ ] v0.5 — Lifecycle, emergency updates, historical decisions and opt-in safe AIA; research CRL/OCSP (#7).
- [ ] v1.0 — Stable SDK/schema, reproducibility, governance, independent security review and multiple integrations (#7).

Master: #1. International research (AATL, EU trusted lists) follows China source research. No real user documents as fixtures.

## v0.1 implementation status

- Inventory, provenance storage, SM2 parsing and direct issuer discovery: merged in #8 and #9.
- Local scoped policy, provenance reviews, decision evaluation: merged in #10. Production trust material, signed snapshots, independent evidence verification, complete path validation remain separate gates.

- Derived index, combined search/pagination and unified local inventory + supplied policy validation: merged in #11; no persistent database or trust authority.

- Offline embedded Schema runtime and empty registry initialization, CLI smoke tests and release-readiness checklist: merged in #12. v0.1 is a developer preview only; license decision, final CI/review and release approval remain gates.

## v0.2 research

- SHECA selected official listing metadata and offline candidate intake preview: merged in #13. Binary acquisition, independent fingerprint/evidence review, redistribution and scoped decisions remain open.

- Observed SHECA auxiliary download endpoints, third-party fingerprint leads and explicit bounded acquisition/audit: merged in #14. Actual download/byte verification and redistribution review remain pending.

- Manual report-only Certificate Research workflow, explicit bounded batch and selected SATL indexed name leads: merged in #15. First actual runner acquisition results, fingerprint-based SATL matching, redistribution review and CA policy evidence are pending.

- Local certificate relationship graph and bounded candidate path enumeration: merged in #16. No complete path validation or production trust; actual research run and reviewed real CA data remain pending.

- Explicit local CA-set path validation and local policy binding: merged in #17. No authenticated release, revocation or business-purpose authorization.

## v0.3 distribution foundation

- Deterministic unsigned local snapshot builder and verifier: merged in #18 (CI not verified). Signature authentication, TUF evaluation, persistent rollback/freeze protection and approved release data remain pending.

- Local research Ed25519 signature and threshold verification, explicit time and caller checkpoint checks: merged in #19. Automatic CI suspended by owner; manual checks retained. TUF production integration, authenticated key rotation and durable rollback state remain separate gates.

- Append-only local research installation and persistent checkpoint, reauthenticated SDK loader: PR #20. Cooperative local locking, bounded history; no authenticated production update, root rotation or hostile local rollback resistance.

- Experimental isolated go-tuf/v2 client adapter: merged in #21. Top-level metadata refresh, target verification, explicit root pin and persistent protected cache. Dependency lock/execution, signed fixture, publisher and application checkpoint integration pending.

- Offline initial TUF root and static repository candidate generation: merged in #22. Four disjoint role key sets, thresholds, linked metadata hashes, consistent-snapshot naming. No rotation, publisher version ledger, deployment or authenticated installation. Dependency lock and executable tests remain pending.

- TUF authenticated research installation and offline evidence loader: PR #23. Initial-root v1, version-aligned publisher profile only; protected filesystem and independent root pin. End-to-end synthetic TLS fixture added, not executed. Rotation evidence, dependency lock and production trust gates pending.

- SigLens candidate exchange v1 and loaded-view issuer discovery: merged in #24. Explicit intermediate candidates only, no authenticated release trust.

## v0.4 Explorer

- Static Cloudflare Workers research preview with client-side catalog search, detail/provenance leads, SATL name references and empty policy templates: merged in #25. No production graph, approved data publication, deployment or signed release yet.

- Interactive Explorer evidence constellation: merged in #26. Direct source/name/fingerprint associations only, no cryptographically verified issuer edges until approved CA data exists.

## v0.5 lifecycle

- DER-backed validity monitoring and bitemporal local policy history: merged in #27. No automatic trust changes, revocation inference or emergency release channel.

- Local emergency restrictions, append-only policy collection comparison, and fresh-evidence reauthorization guard: merged in #28. No production incident distribution, authenticated baseline ledger or global cross-policy kill switch.

- Offline direct-issuer CRL and OCSP evidence inspection, explicit time cutoffs and conflict reporting: merged in #29. Chain integration, evidence persistence and delegated responders remain pending.

- Private content-addressed revocation observations and all-path revocation inspection: merged in #30. Independent local storage, explicit observation cutoff, no public snapshot/OCSP data publication or trust promotion.

- Explicit single-hop HTTPS AIA research acquisition and local issuer matching: merged in #31. DNS/IP pinning, conservative IPv4-only egress profile, offline audit/import separation. No automatic recursive fetch or trust authorization.

- Local CA release-candidate review dossier, exact snapshot binding, required source/redistribution/scope/disclosure review and evidence artifact verification: merged in #32. No reviewer authentication, actual CA review or production publication.

- Pinned role-key review signatures and threshold local release approval: merged in #33. Exact snapshot/dossier/signature-set binding, short validity window. Publisher enforcement, independent key ceremony, rotation and durable release baseline remain pending.

- Reviewed TUF publication staging gate, cross-config role separation and pinned snapshot transition validation: merged in #34. Caller-owned baseline, no persistent publication ledger, root rotation or deployment yet.

- Persistent private reviewed-build ledger, sequential immutable records, hash links, exact byte export and optional independent head pin: merged in #35. No live publication, external tamper-proof checkpoint or rotation.

- Dual-threshold TUF root rotation and offline chain/repository verification: PR #36. Isolated research builder; reviewed ledger and online/offline installed-state migration pending.

- Persistent root chains in reviewed publication ledger and network/offline client installation: PR #37. V1 compatibility, exact history prefix, numbered archive and fail-closed mismatch. Independent client-side release approval and rotation-specific reviewer authorization remain pending.

- Public threshold release credential embedded in TUF targets custom metadata; independent pinned strict online/offline client mode: PR #38. No private evidence publication or extra network request. Production release validation pending.

- Static publication preparation and preflight: PR #39. Full authorized ledger history, pinned manifest delta, bounded static assets, timestamp freshness, separate no-worker release config. No cloud API or deployment. Production validation remains open.

- Manual two-module release validation, dependency-lock candidate artifacts, CLI negative smoke cases, rotated static-directory strict client integration and scriptless config guard: PR #40. No PR/push triggers or deployment. Actual Go execution and locked module acceptance still required.

- Offline pinned SHECA batch candidate intake with preflight, source catalog binding and idempotent provenance: PR #41. Real certificate acquisition, actual Go build/lock and human review remain pending.

- CFCA/BJCA/GDCA multi-CA research catalog, separate chain listings and exact-name fingerprint leads, offline local audit: PR #42. No real certificate acquisition or policy approval. Source review and dependency-lock validation pending.

- Strict offline CA bundle parsing, pinned private archive, matched-member import with original container SHA-256: PR #43. No network acquisition, trust or publication; Go validation and real CA material pending.

- Multi-CA Explorer integration: PR #44. Combined static source projection, authority and research-type filters, scoped evidence graph, 256 KiB catalog module budget. No real DER or trust promotion.

- Local immutable acquisition archive, per-listing reuse/lock, exact original bytes and source catalog binding, pinned offline inspection/export/import: PR #45. Real acquisitions and Go locked validation still pending.

- Private CA evidence review workspace and immutable evidence staging: PR #46. Snapshot/dossier task identity, exact acquisition provenance links, CA technical context, bounded cached artifact diagnostics, no automatic approval. Actual CA evidence and locked Go validation pending.

- Bundle archive linkage, diagnostic review queue and cross-snapshot evidence reference reuse: PR #47. New dossier entirely pending; no automatic approval, cloud dependency or publish. Real data and locked validation pending.

- Pinned Registry release diff and structural consumer impact report (PR #48): certificate/provenance deltas, policy declarations and recorded decision/review changes, optional strict transition. No effective trust or production release claims.

- Effective local authorization impact (PR #49): same-cutoff snapshot comparison, optional earlier cutoff on previous snapshot, shared inventory index and separate certificate validity; no actual path or production trust claim.

- Certificate path impact (PR #50): explicit same-scope local path comparison, shared detached revocation evidence and optional replacement comparison; no production trust claim.

- Strict authenticated consumer SDK (PR #51): offline verified installed sessions, expiry bound, independent checkpoint options, candidate/query/policy/path and live-session comparison APIs. SigLens integration and locked build pending.

- Independent strict online refresh checkpoint: reject lower sequence/root and same-sequence conflicts before target download, recheck exact envelope, SDK checkpoint export and CLI flags. External storage and locked Go acceptance pending; no extra cloud operations.

- Recoverable final strict installation commit: private complete pending evidence journal outside immutable history, no-replacement link, explicit offline recovery with exact current cache/root/credential and optional checkpoint, idempotent post-link cleanup. Earlier TUF metadata/root interruptions and locked Go acceptance remain pending.

- Explicit strict forward root-cache recovery: repair only an intact signed archive ahead of an exact cached prefix, pinned destination, authority role separation, installed baseline and no rollback metadata removal. Offline repair is not release acceptance; normal strict refresh still required. Other metadata interruption repair and locked Go validation pending.

- Strict offline state diagnostics: bounded archive/cache and latest evidence inspection, signed expiry, optional checkpoint, lock and pending recovery guidance. No automatic repair or network; locked Go validation pending.

- Strict explicit update orchestrator: plan/open/root repair/pending recovery/one online refresh modes, action-stage reporting and exact session/checkpoint binding. No automatic bootstrap, retries, fallback or new cloud operations; locked Go acceptance pending.

- Strict target reuse and transfer reporting: unchanged installed release skips redundant target transfer only after current signed metadata, credential, checkpoint and target length/hash checks. New releases still download; no new cloud bindings, cache format or telemetry. Locked Go acceptance pending.

- Public Explorer Research Preview reported deployed at trust.m78u.com on 2026-11-27. Public-source preparation: MIT/NOTICE, security and contribution policy, private workspace ignores and explicit visibility gate. Full Git/GitHub history audit, third-party rights/license review, dependency locks and tests, and owner visibility approval remain pending.

- Pre-public audit preflight: bounded offline reachable-tree/blob inspection with redacted object identifiers, private-path and selected credential-marker review, synthetic deleted-history/branch-only/partial-clone test fixtures. Independent full clone scan, rights review, GitHub metadata review and locked validation remain required; no visibility change.

- Dependency acceptance tooling: independent lock-only resolution and selected Go module graph/license evidence, two Node fixture tests passed. Actual Go 1.26 resolution, lock commit, dependency rights review and locked tests remain open. Private manual artifacts only; no automatic checks or deployment.

- Offline CA acquisition queue and exact fingerprint inventory coverage across SHECA/CFCA/BJCA/GDCA: one validated index, catalog digests, separate asserted URL matching and explicit archive NOT_CHECKED. No network or trust approval; pinned archive coverage and actual acquisition remain separate.

## Current release checkpoint — v0.2 China CA Registry Research

0.1.0 Developer Preview source and Apple Silicon Homebrew installation are already reported successful. This does not complete a verified CA dataset. Prioritize the existing v0.2 order: SHECA actual private original acquisition and fingerprint/relationship analysis, independent source/usage and redistribution review, then remaining CA research. The explicit first three SHA-256-backed SHECA archive batch and independent-pin candidate import path are in [acquisition archive](ACQUISITION-ARCHIVE.md#v02-first-real-sheca-acquisition-batch). Actual acquisition and full locked validation are still required. No new release tag or production trust anchors before independent review; v0.3 authenticated publication remains a separate gate.

- Release acceptance checkpoint: [v0.2 acceptance](V02-RELEASE-ACCEPTANCE.md) separates current source validation, real CA evidence and human review from v0.3 production distribution. No new tag until the applicable gates are met. The 0.1.0 validation is historical, not inherited by main.

- Owner-published source-only [v0.2.0-preview.1](https://github.com/M78U/trust-registry/releases/tag/v0.2.0-preview.1), exact tag `45cc3aad74d93ade0fbfde44996e5f44739deb6d`, reported clean locked validation passed on macOS ARM64 Go 1.26.11. v0.2 data milestone remains open. Homebrew stays on 0.1.0 pending package-specific acceptance. No production anchors or actual dataset.

- Maintainer stage 1: [private source observations](SOURCE-MONITOR.md), fixed catalog URLs, explicit bounded fetch/local capture, independent pin comparison and raw-body change review signal. No semantic membership inference, scheduler, production CA changes or new release. Homebrew preview formula updated; test runner blocked in Bundler, direct installed acceptance not yet reported.

- Maintainer stage 2: private bounded per-source/mode observation store, indexed exact replay, idempotent append and read-only due plan; no automatic network or trust update. See [source monitoring](SOURCE-MONITOR.md#stage-2-persistent-local-observation-index-and-advisory-plan).

- Maintainer stage 3: explicit bounded online check coordinator, lock-scoped due check and capture/append, partial failure and request accounting; no scheduler, automatic retry or trust changes. See [source monitoring](SOURCE-MONITOR.md#stage-3-bounded-explicit-incremental-run).

- Maintainer stage 4: persisted pre-request reservations, bounded per-source cooldown, failure status and successful observation supersession shared by plan/run. No scheduler, network retry loop, new cloud resource or trust change. See [source monitoring](SOURCE-MONITOR.md#stage-4-persisted-attempt-cooldown).

- Maintainer stage 5: experimental SHECA table projection from exact pinned private HTML observation using a separate Python standard-library adapter; strict three-section/column shape, deterministic row normalization and duplicate-claim handling. Synthetic tests passed; raw live HTML acceptance pending, no trust or endpoint changes. See [source monitoring](SOURCE-MONITOR.md#stage-5-sheca-structured-table-adapter-experimental).

- Maintainer stage 6: experimental semantic comparison of two pinned SHECA observations; fingerprint-claim groups, explicit new/not-observed/field changes, ambiguous groups, duplicate-count signal and failure refusal. No inferred certificate identity, live-page validation or trust promotion. See [source monitoring](SOURCE-MONITOR.md#stage-6-semantic-comparison-of-sheca-listing-claims).
