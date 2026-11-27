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
- Local scoped policy, provenance reviews, decision evaluation: current PR. Production trust material, signed snapshots, independent evidence verification, general schema engine and complete path validation remain separate gates.

- Derived index, combined search/pagination and unified local inventory + supplied policy validation: PR #11; no persistent database or trust authority.
