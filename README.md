# M78U Trust Registry

**Discover trust. Verify independently.**

Independent, open-source PKI trust infrastructure by M78U Labs. Planned explorer: trust.m78u.com. The first consumer is [SigLens](https://github.com/M78U/siglens/issues/23), but this project is independently versioned.

Certificate discovery never implies trust. Trust is explicit, scoped, auditable and offline-first. No system trust fallback. Unknown is not trusted.

## Current status

Pre-release foundation. No real CA certificates or default trust anchors. This initial implementation parses standard X.509 DER and PEM and emits candidate records; it does not resolve trust, persist a registry, or verify snapshots. SM2 support is planned.

```sh
go test ./...
go run ./cmd/trust-registry inspect certificate.cer
go run ./cmd/trust-registry import --source https://example.org/ca certificate.cer
```

Import currently previews JSON only; it never creates trust or downloads source URLs. Use public CA certificates only, not personal documents or private keys.

## Design

[Architecture](docs/ARCHITECTURE.md) · [Data model](docs/DATA-MODEL.md) · [Trust policy](docs/TRUST-POLICY.md) · [Threat model](docs/THREAT-MODEL.md) · [Governance](docs/GOVERNANCE.md) · [Release](docs/RELEASE.md) · [Roadmap](docs/ROADMAP.md)

Master roadmap: [#1](https://github.com/M78U/trust-registry/issues/1).
