# Contributing

Thanks for helping make independent PKI research more transparent. This project separates candidate discovery, distribution authentication and trust decisions; none implies the others.

## Development

- Start from current main, use a work branch and open a PR; no routine direct main changes. Keep changes bounded and include tests, documentation and explicit limitations.
- Use Go 1.26.x and Node >=20. Run main-module tests and isolated tools/tuf-client tests independently; see [release validation](docs/RELEASE-VALIDATION.md). Run `cd web && npm test && npm run build` for Explorer changes. Report actual results; a merged PR is not proof of validation. Automatic PR/push checks remain disabled until the owner changes that policy.
- Use synthetic generated certificates and keys in tests. Do not commit real default trust anchors, credentials, personal certificates/documents, production signing material, private review evidence, acquisition originals, local ledgers or installed state. Prefer a private directory outside the repository.
- Keep local verification offline by default; make networking explicit, bounded and privacy-preserving. Avoid new cloud services, background polling, unbounded requests or writes without a justified design review.
- Source collection, source verification, redistribution permission and trust authorization require separate evidence and independent review. Do not use CA names, source URLs or fingerprint leads as automatic proof of identity or trust.
- Contributions to MIT-covered software and original documentation must be yours to license under MIT. Do not submit third-party material without provenance and permission; see [NOTICE](NOTICE.md). No brand or third-party data rights are implied.

Security vulnerabilities should be reported privately using [SECURITY.md](SECURITY.md), not in a public PR. See [governance](docs/GOVERNANCE.md) for trust-specific review requirements.
