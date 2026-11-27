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

## CA source research (v0.2)

`trust-registry sources list`, `sources inspect uca-root-g2` and `sources preview --id uca-root-g2 FILE` expose a selected SHECA research catalog and offline byte comparison. Publisher SHA-1 is a legacy listing cross-check only; SHA-256 remains certificate identity. No certificate bytes are bundled or written by preview; no source authenticity, redistribution permission or trust is inferred. See [SHECA research](docs/research/SHECA.md).

`trust-registry sources endpoints` lists observed acquisition URLs; `sources fetch --id uca-sm2 --out FILE` explicitly downloads a bounded original certificate to a new local file, checks listing hashes and outputs an unreviewed report. `sources audit --id uca-sm2 FILE` runs offline. Other endpoints without external SHA-256 require `--allow-legacy-only`. Fetch is research-only; ordinary validation and discovery remain offline. No trust promotion or automatic registry import.

`trust-registry sources research` runs the explicit report-only SHECA batch (SHA-256 leads by default; `--include-legacy` opts into weaker legacy-only checks). The manually triggered Certificate Research Actions workflow saves JSON only. `sources satl` lists selected name-only SATL research leads; see [SATL research](docs/research/SATL.md). No program membership or trust is inferred.

## Certificate relationship graph

`trust-registry graph --registry ./local-registry` exports deterministic candidate nodes and edges. `trust-registry paths --registry ./local-registry --certificate signer.cer` enumerates matched direct-issuer paths without saving the input; `--fingerprint HEX` selects a stored CA. Self-signature, missing issuer, cycle and depth limit are explicit path terminal states. No trusted root or complete path verification is established. See [relationship graph](docs/RELATIONSHIP-GRAPH.md). Do not publish graphs containing a private signer certificate.

## Offline path validation

`verify-path --registry ./local-registry --policy local-policy.json --purpose document-signing --at 2026-01-02T00:00:00Z --known-at 2026-01-02T00:00:00Z signer.cer` evaluates only locally authorized anchors and explicitly listed intermediates. A valid technical path does not establish business purpose, revocation status or trust. See [path validation](docs/PATH-VALIDATION.md).

## Local research snapshots

`trust-registry snapshot build --registry ./local-registry --sequence 1 --revision GIT_SHA --created-at RFC3339 --expires-at RFC3339 --out local-snapshot.json` builds a deterministic unsigned local envelope. Repeat `--policy FILE` for explicitly supplied policy documents. `trust-registry snapshot verify local-snapshot.json` checks manifest hashes and semantic consistency, not authenticity, freshness or rollback. See [snapshot format](docs/SNAPSHOT.md). Do not publish research snapshots before redistribution and release authorization.

### Local research signatures

`snapshot sign-research --key KEY.pem --out signature.json SNAPSHOT` and `snapshot authenticate-research --public-key PINNED.pem --signature signature.json --threshold 1 --at RFC3339 --bootstrap SNAPSHOT` demonstrate offline research signature verification. Keys must be independently obtained; use a protected local checkpoint on subsequent checks. See [research authentication](docs/RESEARCH-AUTHENTICATION.md). Not production release trust. Automatic PR/push CI is temporarily disabled; run CI manually before release.
