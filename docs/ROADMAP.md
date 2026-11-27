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
