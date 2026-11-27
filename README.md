# M78U Trust Registry

**Discover trust. Verify independently.**

Independent, open-source PKI trust infrastructure by M78U Labs. Planned explorer: trust.m78u.com. The first consumer is [SigLens](https://github.com/M78U/siglens/issues/23), but this project is independently versioned.

Certificate discovery never implies trust. Trust is explicit, scoped, auditable and offline-first. No system trust fallback. Unknown is not trusted.

## Current status

Pre-release foundation. No real CA certificates or default trust anchors. The initial implementation parses standard and SM2 X.509 DER/PEM and persists CA candidates and independent source assertions in a local content-addressed inventory. Local policy evaluation is experimental and explicitly unauthenticated; no production trust evaluation or snapshot verification yet. Direct issuer discovery reports local candidate evidence only, never trust.

```sh
go test ./...
go run ./cmd/trust-registry init --registry ./local-registry
go run ./cmd/trust-registry inspect certificate.cer
go run ./cmd/trust-registry import --registry ./local-registry --source https://example.org/ca certificate.cer
go run ./cmd/trust-registry list --registry ./local-registry
go run ./cmd/trust-registry find --registry ./local-registry --fingerprint SHA256
go run ./cmd/trust-registry provenance --registry ./local-registry --fingerprint SHA256
go run ./cmd/trust-registry validate --registry ./local-registry
go run ./cmd/trust-registry discover --registry ./local-registry signer.cer
```

Import persists CA candidates only, never creates trust and never downloads source URLs. Source URLs must be public HTTPS without query, credentials or fragment. The default inventory is registry/; use a separate local directory for experiments. Validate checks byte integrity and references, not source authenticity or certificate trust. Operate on a trusted local directory, one writer at a time, on a filesystem supporting hard links; an interrupted import can leave partial state that validation rejects. Never import personal documents, private keys or confidential CA material.

## Design

[Architecture](docs/ARCHITECTURE.md) · [Data model](docs/DATA-MODEL.md) · [Trust policy](docs/TRUST-POLICY.md) · [Threat model](docs/THREAT-MODEL.md) · [Governance](docs/GOVERNANCE.md) · [Release](docs/RELEASE.md) · [Roadmap](docs/ROADMAP.md)

Master roadmap: [#1](https://github.com/M78U/trust-registry/issues/1).

## Direct issuer discovery

Exact DER issuer/subject names or nonempty AKI/SKI equality select candidates. Signature and limited CA constraints are evaluated separately; unsupported signatures, identifier conflicts and unknown critical extensions do not match. No validity time, full path constraints, policy, revocation or trust-anchor evaluation. `trustStatus` is always `NOT_ESTABLISHED`. Names with equivalent but differently encoded DNs may be missed. The candidate scan uses a rebuilt, validated local index, is bounded to 256 matches, and assumes an operator-controlled inventory. No system roots or network requests.

## Local policy evaluation

`trust-registry policy list` and `policy inspect cn.document-signing` expose empty built-in profiles. `policy evaluate --file policy-review.json --registry ./local-registry --at 2026-01-01T00:00:00Z --known-at 2026-01-01T00:00:00Z` evaluates a local review document. It never establishes release authenticity or certificate trust; even explicit local approvals are reported only as `locallyAuthorizedAnchors`. See [policy format](docs/TRUST-POLICY.md).

## Indexed queries and unified validation

```sh
go run ./cmd/trust-registry search --registry ./local-registry --source-host example.org --key-algorithm SM2 --limit 50
go run ./cmd/trust-registry search --registry ./local-registry --ski HEX --issuer 'CN=Example CA'
go run ./cmd/trust-registry validate --registry ./local-registry --policy testdata/policies/empty-cn-document-signing.json
```

All search filters are exact AND matches. Serial/SKI/AKI/fingerprint use canonical lowercase hexadecimal. DN display text and asserted source host are discovery keys only, not proof of identity or source authenticity. Results are ordered by fingerprint; pass nextAfter as --after with the same filters and unchanged inventory to continue. The SDK reuses Store.BuildIndex() across queries; rebuild after any change. No persistent index or authenticated snapshot. Repeat --policy to check multiple local documents against one validated inventory; duplicate policy versions and scope changes under the same ID are rejected. Only supplied documents are checked. Embedded Draft 2020-12 JSON Schema validation is enforced alongside semantic checks; authenticated completeness and certificate path validation remain pending.

## v0.1 release readiness

This is a development-only candidate inventory and policy toolkit, not a trusted root distribution. See [release checklist](docs/RELEASE.md). No production trust dataset is included. The schema runtime compiles all six embedded schemas with format assertions, rejects duplicate keys and external schema references, and validates persisted certificate/provenance JSON and local policy documents. No network access during validation. Semantic and cryptographic checks remain independent.
