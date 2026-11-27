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

### Installed research snapshots

`snapshot install-research --state DIR --public-key KEY.pem --signature SIG.json --threshold 1 --at RFC3339 --bootstrap SNAPSHOT` installs a first authenticated research snapshot. Subsequent installs omit `--bootstrap`; `snapshot load-research --state DIR --public-key KEY.pem --threshold 1 --at RFC3339` reauthenticates the newest record. SDK `snapshot.LoadResearch` exposes detached query and exact-version policy/path evaluation. No production trust. See [local installation](docs/SNAPSHOT-INSTALLATION.md).

`snapshot verify-installed-path` exposes exact installed policy path checks from CLI; `--at` is reliable current time, `--evaluation-time` and `--known-at` are separate historical times. First install requires a new state directory.

## Experimental TUF download client

The isolated `tools/tuf-client` Go module connects to go-tuf/v2 for independently bootstrapped, top-level signed metadata and Registry target retrieval. See [TUF distribution](docs/TUF-DISTRIBUTION.md). Dependency resolution, lockfile and executable testing are pending; not production release or CA trust. Main module and automatic CI configuration unchanged.

Experimental offline `tools/tuf-client/cmd/tuf-publish` builds initial root metadata and a local static TUF repository candidate with separate role keys. See [publisher](docs/TUF-PUBLISHER.md). No live publishing or release authorization.

Experimental TUF `tuf-fetch --install` persists signed metadata and snapshot together; `tuf-load` reauthenticates current local evidence offline. Initial-root v1 profile only; see [TUF installation](docs/TUF-INSTALLATION.md). No production trust; dependency lock and execution pending.

### SigLens candidate exchange

`snapshot export-candidates --snapshot-sha256 HEX --at RFC3339 [--certificate SIGNER.cer] SNAPSHOT` emits a portable candidate-only JSON bundle. See [consumer contract](docs/CONSUMER-CANDIDATES.md). No roots or trust grants; keep local signer input private.

## Registry Explorer research preview

`cd web && npm test && npm run build` creates a dependency-free static research preview in `web/dist`. See [Explorer deployment](docs/EXPLORER.md). The public projection contains only selected source-directory leads and empty policy templates, never certificate bytes or local snapshots. Planned Workers custom domain trust.m78u.com; not deployed.

Explorer includes an interactive evidence constellation with direct catalog/source/fingerprint/name associations, keyboard navigation, relation filters and complete neighbor list. These are research associations, not verified certificate chains.

## Certificate lifecycle

`trust-registry lifecycle --registry DIR --at RFC3339 --warning-days 90` reports validity of DER-backed current inventory at explicit time. `trust-registry policy history --registry DIR --file POLICY.json --fingerprint HEX --at RFC3339 --known-at RFC3339` exposes time-visible decisions and reviews for a declared anchor. Loaded snapshot SDK offers both operations. See [lifecycle](docs/LIFECYCLE.md). No revocation or production trust inference.

## Emergency local policy changes

`policy restrict` proposes an immediate suspension or indefinite distrust for one declared anchor in an exact policy version; `policy check-transition` compares complete previous/next policy document sets. Neither edits existing files nor publishes a release. Positive authorization after a restriction requires new review and decision recorded after it. See [emergency updates](docs/EMERGENCY-UPDATES.md).

## Offline revocation evidence

`trust-registry revocation --issuer issuer.cer --at RFC3339 --known-at RFC3339 --crl local.crl --ocsp local.ocsp signer.cer` verifies a direct issuer pair and explicitly supplied CRL/OCSP evidence. See [revocation evidence](docs/REVOCATION-EVIDENCE.md). No final GOOD status, network or trust grant.

### Private revocation store and path checks

`revocation-store init|import|list` manages local content-addressed CRL/OCSP observations. `verify-path --revocation-store DIR` checks every returned technical path using observations available by the explicit knowledge cutoff. SDK also supports the exact installed snapshot. No certificate trust grant, network or public evidence publication. See [private evidence storage](docs/REVOCATION-STORE.md).

### Explicit AIA research discovery

`aia inspect` lists eligible caIssuers HTTPS URLs offline. `aia fetch` requires exact selected URL and new output file, `aia audit` checks a local candidate, and `aia import` explicitly imports a matched CA as unreviewed. No automatic network during path verification. See [safe AIA](docs/SAFE-AIA.md).

### CA release-candidate review dossier

`review plan SNAPSHOT` generates pending exact-snapshot source identity, redistribution, policy scope and disclosure tasks. `review check --dossier FILE --evidence DIR --at RFC3339 SNAPSHOT` checks complete task membership, reviewer separation and local evidence artifact hashes. No approval default or release authorization. See [CA review](docs/CA-REVIEW.md).

### Authenticated local review approval

`review prepare-approval`, `review sign-task`, `review approve-release`, and `review authenticate-approval` verify per-task signatures and distinct release approver threshold using an independently pinned Ed25519 role configuration. See [review authorization](docs/REVIEW-AUTHORIZATION.md). Local approval only; not TUF publication authority.

### Reviewed TUF staging

The experimental isolated `tuf-publish build-reviewed` mode requires a complete threshold-signed review approval, independent authority/root pins, cross-role key separation and explicit bootstrap or previous snapshot pin with append-only history and sequence advancement. Produces only local staging files; no production release. See [publication gate](docs/PUBLICATION-GATE.md).

### Persistent local publication ledger

`build-ledger` commits reviewed, exact TUF staging bytes under a protected local monotonic ledger; `ledger-export` exports the current valid head without re-signing. See [ledger](docs/PUBLICATION-LEDGER.md). Local build records are not evidence of online publication.

### TUF root rotation (research)

`tuf-publish rotate-root`, `verify-root-chain` and `build-rotated` support consecutive dual-authorized root updates and rotated research staging. The offline SDK verifies staged rotated repositories from independently pinned v1 and current roots. See [root rotation](docs/TUF-ROOT-ROTATION.md). Reviewed ledger and network installation now persist verified numbered root history.

### Persistent root history

Rotated `build-ledger` accepts the full ordered `--root-chain` and `--initial-root-sha256` plus the existing current root pin; exports retain every numbered root. Network client archives independently verified roots and rechecks the full chain on offline load. See [persistent root chain](docs/TUF-PERSISTENT-ROOT-CHAIN.md).

### Independent public release approval

`review prepare-public` / `sign-public` produce a compact threshold-signed receipt. Reviewed TUF builds accept `--public-credential`; strict `tuf-fetch` and `tuf-load` use independent `--authority` and `--authority-sha256` pins. Receipt is embedded in existing Targets metadata, no extra HTTP request or private dossier. See [client release authorization](docs/CLIENT-RELEASE-AUTHORIZATION.md).

### Static release staging

`tuf-publish static-prepare` builds a complete static Explorer/TUF asset collection from a pinned public-authorized ledger and produces a private SHA-256 manifest and delta estimate. `static-check` verifies the exact asset collection before manual deployment using `web/wrangler.release.jsonc`. See [static publication](docs/STATIC-PUBLICATION.md). No Cloudflare bindings or live deployment.

### Manual release validation

Run `node scripts/validate-release.mjs --mode=lock-candidate` with Go 1.26 and Node >=20 to generate dependency lock candidates and exercise both Go modules, all CLIs and Explorer. After reviewed lock files are committed, run `--mode=locked` on a clean checkout. Manual GitHub workflow `release-validation.yml` provides the same checks and short-lived report artifacts. See [acceptance guide](docs/RELEASE-VALIDATION.md). No automatic PR checks or deployment.

### Offline batch CA candidate intake

`sources intake-plan` checks selected local `ID.cer` files against the embedded SHECA catalog and observed endpoints, binds original file and DER hashes, catalog hashes and explicit observation time. `sources intake-apply --plan-sha256` repeats preflight and imports only unreviewed candidates into an initialized local store. No network or trust promotion. See [batch intake](docs/CA-INTAKE.md).

### Multi-CA research leads

`sources multi-ca [--authority CFCA|BJCA|GDCA]` lists selected observed official chain/certificate leads and scoped third-party SHA-256 observations. `sources multi-ca-audit --id ID FILE` checks a single local certificate only when an exact published SHA-256 lead exists. No network, import or trust authorization. See [multi-CA research](docs/MULTI-CA-RESEARCH.md).

### Offline certificate bundle intake

`sources bundle-plan`, `bundle-export`, `bundle-apply` support bounded CA-only PEM, single DER and certificate-only PKCS#7 containers. Retain original bytes and pinned member manifest; explicitly import only exact matched published leads with original container provenance. See [bundle intake](docs/CERTIFICATE-BUNDLE-INTAKE.md).

Explorer now projects four CA research catalogs into one static browser-local index (32 research rows, 8 SHA-256 leads, 7 SATL name leads). Authority/type/track/status filters and source constellation remain research-only. No runtime API or extra asset request.

### Private acquisition archive

`sources archive-fetch` saves exact original bytes and locally asserted observation metadata for an explicit SHECA endpoint, and reuses an intact existing observation without another fetch. `archive-inspect`, `archive-original`, `archive-import` require the independently retained archive digest. See [acquisition archive](docs/ACQUISITION-ARCHIVE.md). No automatic trust or cloud storage.

### Private review workspace

`review evidence-add` stages exact local artifact bytes by SHA-256. `review workspace` checks a pinned snapshot and existing dossier, optionally links independently pinned acquisition observations by exact provenance equality, and reports missing/invalid evidence slots and technical CA properties. Diagnostic only; no automatic approval or evidence conclusion. See [CA review workspace](docs/CA-REVIEW-WORKSPACE.md).
