# Experimental TUF authenticated installation

The opt-in TUF module now supports RefreshAndInstall and LoadInstalled. Use tuf-fetch with --install instead of --out. The same TUF metadata lock covers online refresh, validation and installation. Each installed version is one canonical JSON record with exact signed metadata and Registry bytes, acceptance time, sequence and hash. File sync, local pending journal and no-replacement hard link publish complete records; no automatic pruning, 128-record limit, no directory fsync guarantee. Unexpected files or corrupt newest record fail closed. Do not delete history or restore old backups. Local filesystem and state parents must be protected against hostile changes. Failed installation may have advanced TUF metadata; no automatic reset. A separate download-only operation does not change the accepted installed snapshot; if any of the four cached metadata files differ from the latest installation evidence, offline loading fails closed until a successful refresh/install. This includes a partially advanced cache, even if the prior installation is not expired.

For this first implementation only, the independently pinned initial root v1 and publisher's version-aligned profile are supported. Offline validation uses upstream trustedmetadata.New, UpdateTimestamp, UpdateSnapshot(false), UpdateTargets and VerifyLengthHashes; explicit required SHA-256 links and application sequence equality are checked. Root rotation evidence is not yet retained; installation rejects rotated roots and offline loading rejects any changed cached metadata. Offline loading cannot detect a newer remotely published version or revocation absent a refresh; checks all stored expiry dates at reliable system time. An expired prior installation is checked at its recorded acceptance time only for advancing the checkpoint. Same-sequence changed metadata or payload is rejected, as is a lower sequence. No trust granted by a signed research snapshot.

Core SDK LoadPinnedResearch accepts an independently authenticated exact envelope digest and explicit UTC time; alone it is only an equality/integrity check, not a TUF verifier. The TUF adapter validates evidence first, then returns a detached read-only Loaded view with Find, Search, Policy and VerifyLocalPath. No network during load. Report contains TUF target authentication, versions and registry digest; releaseAuthenticated remains false and trustStatus NOT_ESTABLISHED. Reopen per verification session. No private keys or signer documents stored.

```sh
cd tools/tuf-client
go run ./cmd/tuf-fetch --state STATE --metadata-url HTTPS_METADATA --targets-url HTTPS_TARGETS --root-sha256 INDEPENDENT_PIN --bootstrap-root root.json --install
go run ./cmd/tuf-load --state STATE --root-sha256 INDEPENDENT_PIN
```
Subsequent refresh omits bootstrap-root. Use the independently obtained pin, not a downloaded assertion. Publisher-client-install-load integration test uses a local TLS fixture and synthetic keys; no production material. Tests are not executed and module go.sum remains pending (Go 1.26/proxy unavailable, automatic CI disabled). Not production ready.


## Recoverable final installation commit

After successful download, full envelope verification and installed-baseline checks, the installer stages the complete canonical evidence as private `STATE/pending-install.json` (synced temporary file in the state directory, then rename). Only a complete staged file is linked into `installed/<sequence>.json`; the final record is never replaced. Cleanup removes the journal after the link. The journal uses the existing evidence format. Normal unchanged refresh does not write a journal if none exists. New successfully verified online installs may replace a stale regular journal; never manually copy old metadata or clear rollback history.

An explicit offline strict recovery can complete this final commit if interrupted after staging, or clean the journal if the link already succeeded:

```sh
go run ./cmd/tuf-load --state STATE --root-sha256 INDEPENDENT_PIN \
  --authority AUTHORITY.json --authority-sha256 INDEPENDENT_AUTHORITY_PIN \
  --recover-pending
```

Supply the independently retained `--checkpoint-sequence N --checkpoint-snapshot-sha256 HEX --checkpoint-root-version V` together if available. The SDK equivalent is `RecoverPendingInstall(RecoveryOptions{...})`. It acquires the existing lock, checks canonical configuration and journal bytes, exact equality of all four cached metadata files, full numbered root history from the independent pin, TUF signatures/links and snapshot semantics, independent public review credential, optional checkpoint, installed baseline, and current signed expiry. It preserves the exact evidence bytes and original acceptance time. No network, metadata rewrite, root rollback, private evidence authentication or CA trust. A success report has `recoveredPendingInstall: true`; ordinary load remains separate and refuses stale cache mismatch. Reopen the strict consumer after recovery.

Limitations: this is a recoverable **final commit**, not a transaction across upstream TUF metadata/root writes. If the interruption occurred before the journal was fully staged, or it is expired or mismatches current cache/archive, recovery fails closed; an ordinary verified forward refresh may be needed. The lock is never broken automatically; after a process crash an operator must independently establish that no state writer remains before removing a stale lock. Temporary staging files outside installed history may remain; do not blindly remove records. No guarantee of atomic replacement across all OS/filesystems, directory fsync, power-loss durability, or protection from a hostile local filesystem. Research-only journals are not eligible for the strict offline recovery command; retry a normal research install. No Cloudflare operations or automatic retry.
