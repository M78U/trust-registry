# M78U Trust Registry

**Discover trust. Verify independently.**

Independent, open-source PKI trust infrastructure by M78U Labs. Planned explorer: trust.m78u.com. The first consumer is [SigLens](https://github.com/M78U/siglens/issues/23), but this project is independently versioned.

Certificate discovery never implies trust. Trust is explicit, scoped, auditable and offline-first. No system trust fallback. Unknown is not trusted.

## Current status

Pre-release foundation. No real CA certificates or default trust anchors. The initial implementation parses standard X.509 DER/PEM and persists CA candidates and independent source assertions in a local content-addressed inventory. No trust evaluation or snapshot verification yet. SM2 support is planned.

```sh
go test ./...
go run ./cmd/trust-registry inspect certificate.cer
go run ./cmd/trust-registry import --registry ./local-registry --source https://example.org/ca certificate.cer
go run ./cmd/trust-registry list --registry ./local-registry
go run ./cmd/trust-registry find --registry ./local-registry --fingerprint SHA256
go run ./cmd/trust-registry provenance --registry ./local-registry --fingerprint SHA256
go run ./cmd/trust-registry validate --registry ./local-registry
```

Import persists CA candidates only, never creates trust and never downloads source URLs. Source URLs must be public HTTPS without query, credentials or fragment. The default inventory is registry/; use a separate local directory for experiments. Validate checks byte integrity and references, not source authenticity or certificate trust. Operate on a trusted local directory, one writer at a time, on a filesystem supporting hard links; an interrupted import can leave partial state that validation rejects. Never import personal documents, private keys or confidential CA material.

## Design

[Architecture](docs/ARCHITECTURE.md) · [Data model](docs/DATA-MODEL.md) · [Trust policy](docs/TRUST-POLICY.md) · [Threat model](docs/THREAT-MODEL.md) · [Governance](docs/GOVERNANCE.md) · [Release](docs/RELEASE.md) · [Roadmap](docs/ROADMAP.md)

Master roadmap: [#1](https://github.com/M78U/trust-registry/issues/1).
