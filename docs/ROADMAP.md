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

- Deterministic unsigned local snapshot builder and verifier: PR #18. Signature authentication, TUF evaluation, persistent rollback/freeze protection and approved release data remain pending.
