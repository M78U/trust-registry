# v0.2 release acceptance checkpoint

This is the existing China CA Registry Research milestone, not a new trust model or an authorization to publish. The source reference for the review at the start of this checkpoint is main `d012be4ab0cb7c8e7a79b3c71eaf63366b7768a1`, 15 commits ahead of the 0.1.0 tag (`0477dd115adb86f32b6b3ac41a8018bf4b087ade`). Re-evaluate at the actual final release revision. The repository is public, the source-only 0.1.0 Developer Preview was released by the owner, and the current official Homebrew formula remains at 0.1.0 for Apple Silicon source builds. Do not move an existing tag or silently change the formula.

## Decision

The v0.2 source/candidate research functionality is ready to enter acceptance, not ready to publish as a completed v0.2 milestone. A separate software-only preview release could be considered after successful validation and explicit owner review, but does not meet the v0.2 real-data milestone. Do not invent a version or release scope to bypass the gates. The existing roadmap remains the authority.

| Gate | Status at checkpoint | Evidence needed |
| --- | --- | --- |
| v0.1 published source/tag | Established | Existing owner release and exact tag |
| v0.1 Apple Silicon installation | Reported successful | Existing scoped Homebrew acceptance |
| v0.2 candidate intake tooling | Implemented, unvalidated at current revision | Current locked CLI and regression tests |
| First real SHECA acquisition | Not demonstrated | Three exact pinned original archives or documented actual blockers |
| Real identity and relationship analysis | Not demonstrated | Replay of original bytes, independent fingerprint/source material, technical report |
| Purpose and redistribution review | Not demonstrated | Actual CP/CPS, intended scope and applicable terms or permission; authorized human conclusions |
| Remaining China CA research scope | Incomplete | CFCA/BJCA/GDCA and SATL evidence, unresolved leads documented; no fabricated identities |
| Current revision developer validation | Pending | Clean committed-lock acceptance for both modules and applicable platform checks |
| Software release review | Pending | Scope, exact commit, license/notice review including outstanding nested/embedded material, independent review and owner approval |
| v0.3 authenticated distribution | Separate gate | Approved dataset, key ceremony, strict integration and live deployment acceptance |

## Run current source acceptance

On the operator's machine, use Go 1.26 and Node >=20, a clean checkout of the exact candidate revision, and the existing manual script:

```sh
git fetch origin
git switch main
git pull --ff-only
git status --short
node scripts/validate-release.mjs --mode=locked
```

The script now also exercises empty-inventory acquisition coverage, the three initial SHA-256-backed SHECA catalog routes, explicit pin requirements, invalid batch selection/import and malformed local original rejection. All are offline. Successful import and relationship behavior is covered by the synthetic Go fixtures; actual real originals are a separate operator run. Do not treat a negative CLI smoke check as proof of real acquisition or transport correctness. The old 0.1.0 binary lacks newer commands.

The operator previously reported a locked pass for the 0.1.0 candidate. A pass on that commit does not transfer to main. Retain current report.json privately and verify its exact source revision, all stages and unchanged locks. The current implementation environment has Go 1.23.2, not Go 1.26; no fresh full pass is claimed. No automatic workflow dispatch.

## Real data acceptance

Follow the existing [first SHECA batch](ACQUISITION-ARCHIVE.md#v02-first-real-sheca-acquisition-batch). The initial IDs are uca-global-g2, uca-sm2, unitrust-global-r3. If online retrieval is unavailable, use the explicit [local original fallback](ACQUISITION-ARCHIVE.md#local-original-fallback-no-automatic-network-receipt). Keep files and pins private, use exact independent observations and record failures rather than weakening checks. Run pinned coverage with --technical, inspect the originals, and complete the actual source, scope and rights review. Use the existing [review workspace](CA-REVIEW-WORKSPACE.md) for exact snapshot-bound evidence. A local pin, TLS/SM root-list listing, self-signature, graph match or candidate import is not a trust grant.

Do not publish raw certificates, archive JSON, private evidence, reviewer material or unsigned snapshots as trusted data. A source software release is distinct from v0.3 authenticated production distribution. No default anchors, production keys, cloud deployment or tag is created by this checkpoint.

## Release action

When the existing milestone and release review gates are satisfied, choose the exact version and commit, prepare release notes stating the actual scope and limitations, review the source/rights inventory, then use an owner-authorized GitHub Release operation. Update Homebrew separately after reviewing the exact new source and build/license acceptance. Update the Explorer version link only after the release exists; do not redeploy the preview over any production release assets. Preserve the old tag and all independent pins. No automatic release or deployment on merge.

## Source-only preview released — 2026-11-27

Owner reported publishing [v0.2.0-preview.1](https://github.com/M78U/trust-registry/releases/tag/v0.2.0-preview.1). The GitHub tag resolves to the exact validated commit `45cc3aad74d93ade0fbfde44996e5f44739deb6d`. The owner supplied complete passing locked validation output and confirmed report status LOCKED_DEVELOPER_VALIDATION_PASSED, sourceRevision matching the tag, sourceClean=true, Go 1.26.11 darwin/arm64. The GitHub connector verified tag/commit identity, not independent Release-object metadata. This is the software-only pre-release scope described above, not completion of v0.2 CA data research. Cross-platform validation, actual CA evidence, usage and redistribution reviews remain outstanding. Homebrew remains at 0.1.0 until new exact-release package acceptance; preserve both immutable tags. Website source preview links are updated separately from package version and deployment.
