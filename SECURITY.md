# Security policy

## Supported status

M78U Trust Registry is a research/developer preview, not a production CA trust store. The public Explorer is a research directory; it is not a trust bootstrap or an authenticated release. The experimental TUF implementation and strict consumer are intended for independent verification, but the committed-lock validation and independent security review are not yet complete. No supported production release or guaranteed response SLA is claimed.

## Report a vulnerability privately

If GitHub private vulnerability reporting is enabled, use [Report a vulnerability](https://github.com/M78U/trust-registry/security/advisories/new). If that route is unavailable, contact the maintainers through an existing private channel or ask for one in a minimal public issue without disclosing the vulnerability. Do not post exploit details, unredacted secrets, personal signing certificates, documents, private infrastructure information or private evidence in issues, PRs, discussions or public logs.

Provide the affected commit/version, affected component, expected and observed behavior, security impact, a minimal synthetic reproduction and proposed mitigation if available. Use only local/synthetic inputs or systems you are authorized to test. Do not probe real CA infrastructure or collect user data.

Maintainers should acknowledge reports when possible, investigate privately, agree a coordinated disclosure timeline and publish remediation information once safe. No fixed response time or bounty is promised. For suspected release-key compromise, suspend affected publication, retain evidence privately, rotate/revoke affected credentials through the appropriate independent authority, and coordinate a reviewed forward-only recovery; do not silently roll back a published stream.

See [threat model](docs/THREAT-MODEL.md), [governance](docs/GOVERNANCE.md) and [public-source readiness](docs/OPEN-SOURCE-READINESS.md). Private vulnerability reporting and repository security settings must be verified by the owner before public visibility.
