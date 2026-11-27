# Public-source readiness gate

The Explorer is already deployed as a public Research Preview at https://trust.m78u.com/ (operator reported successful deployment on 2026-11-27). Public website access, public source visibility, signed dataset publication and production CA trust are separate decisions. Do not infer authorization for one from another.

## Checklist before making the repository public

- [ ] Confirm rights holder, MIT license grant, and contribution history; review NOTICE.md and rights of all brand assets and research-source material, including earlier revisions.
- [ ] Scan all accessible Git history (including branches, tags and PR refs where available) for credentials, private keys, confidential files and personal data. Review findings privately; no publication until resolved.
- [ ] Review GitHub issues, PRs and review comments, releases/attachments, Actions logs/artifacts, wiki, discussions, LFS objects and other public-facing metadata independently; a Git history scan cannot cover them.
- [ ] Review both Go module dependency graphs, third-party license texts and required notices; complete lock-candidate and committed-lock validation on the exact proposed public commit. Run the existing manual cross-platform CI as appropriate and review failure logs.
- [ ] Independently review security-sensitive code and open findings, especially strict TUF state, parser bounds, private data isolation and publication gates.
- [ ] Confirm brand and third-party data publication rights; remove/replace material that cannot be cleared. A license exclusion is not permission to distribute.
- [ ] Owner verifies private vulnerability reporting, repository rules/branch protection, review requirements and Actions permissions. Consider untrusted fork contributions, secret access, build/deployment triggers and approval requirements. Do not expose privileged credentials to PR code.
- [ ] Verify the site is clearly research-only; verify current public assets contain no private or unpublished material. Keep automatic deployment from overwriting future signed TUF history.
- [ ] Owner records the exact reviewed source commit, audit dates, validation results and explicit public-visibility approval privately.

MIT license, NOTICE, SECURITY, CONTRIBUTING, README status and ignore rules are preparation artifacts, not proof of clearance. This checklist deliberately does not mark the audit or test gates complete. Do not change repository visibility automatically. The preflight added in this phase is advisory and does not update checklist status.

## Private local history audit

A dependency-free bounded preflight is now available in the reviewed source checkout (Node >=20, Git). Run the script against a separately authenticated, complete local mirror. The script does not fetch or mutate the mirror; use a trusted, ordinary full clone without grafts or alternate object stores.

```sh
node --test scripts/audit-public-source.test.mjs
node scripts/audit-public-source.mjs --repo=/private/path/trust-registry-audit.git
```

The preflight visits distinct trees reachable from local Git refs and each distinct referenced blob, including files removed from the current tree. It checks selected private workspace and sensitive file names, symlinks, submodules, binary/oversize blobs, LFS pointers and a small set of high-signal text patterns. It reports object IDs and SHA-256 of flagged paths instead of raw paths, matched text or secret values. Inspect the flagged objects/paths privately with Git; never publish the report. For example, use `git log --all --find-object=OBJECT_ID --format='%H'` to identify commits for a blob and inspect their trees privately.

Exit 0 (`PREFLIGHT_NO_MARKERS_FOUND`) is not clearance, exit 1 (`REVIEW_REQUIRED`) means review candidates, exit 2 (`INCOMPLETE`) means invalid clone, changed refs, Git error or budget exceeded. Bounds: 2,000 trees, 200,000 entries, 10,000 distinct blobs, 2 MiB per inspected blob, 128 MiB total inspected bytes and 10,000 findings. Binary and oversize blobs require separate review. The preflight rejects shallow/partial clones and does not scan object contents referenced only by non-commit refs, inaccessible or unreachable objects, commit messages, GitHub metadata, encoded secrets or arbitrary secret formats. It does not resolve LFS objects or submodules. Use the independent scanner and manual review below as separate required gates; never treat this script as a replacement for them.


Use an authenticated, isolated local clone on trusted storage. Do not send credentials or scan output to public services. Use a reviewed and pinned secret-scanner version (for example Gitleaks v8.24 or newer with its git subcommand); inspect its help and check its exit status. Example:

```sh
git clone --mirror https://github.com/M78U/trust-registry.git trust-registry-audit.git
cd trust-registry-audit.git
git for-each-ref --format='%(refname)'
git log --all --format= --name-only | sort -u
gitleaks git --redact --log-opts="--all" .
```

Use an authenticated Git credential helper, never a token embedded in the clone URL. A mirror includes advertised refs; separately enumerate and fetch PR head/merge refs where accessible, review deleted or otherwise inaccessible history limitations, and scan again if refs change. Inspect binary and LFS content, archives, ignored/untracked content intended for release, private-source references, commit messages and authorship metadata as well. Review synthetic test key findings manually, never broadly suppress all certificate/key extensions. A clean scanner result is not proof of no exposure. Use a fresh audit after the final commit and any history remediation.

If a real credential is found, revoke/rotate it first; removing the file or rewriting Git history alone is insufficient. Do not paste a secret into an issue or commit an audit report. Keep records outside Git. Coordinate any required history remediation, including PR refs and existing clones, with the owner and GitHub; do not force-push main as a routine change. If historical rights or secrets cannot be cleared, consider an independently reviewed clean public-source repository without exporting private history. Do not treat making a repository private again as undoing disclosure.

## Private material separation

Use a protected workspace outside the checkout for acquisition originals, CA review evidence, key material, approval artifacts, ledger state, external checkpoint receipts and installed state. The root ignore list protects common names and key containers only; arbitrary paths and previously tracked files are not protected. Review staged changes before every commit. The existing static build allowlist remains the website boundary; never publish a workspace, audit report, private ledger or arbitrary build directory.

## Test and license validation

See RELEASE-VALIDATION.md for manual lock-candidate then locked acceptance. Both Go module lockfiles are committed as of #64. See [third-party notices](../THIRD-PARTY-NOTICES.md) for the scoped CLI license inventory added in #65. Re-run locked validation on the final candidate; do not hand-create checksum files. Review lockfile changes and actual dependencies, including license obligations, then record the successful tests and independent security review. No production trust release, signature ceremony, or actual CA-data approval is authorized by this gate.

Only after all applicable gates are satisfied should the owner use GitHub repository Settings to change visibility. GitHub issues and historical material can become public too. This PR does not make the repository public, enable security settings, start workflows or deploy Cloudflare.
