# SHECA source research — 2026-11-27

Authority: Shanghai Electronic Certification Authority (上海市数字证书认证中心有限公司), research identifier cn.sheca.

Primary listing: https://www.sheca.com/repository (CA Certificates section; root, intermediate and disuse tables). This PR records 17 selected rows in pkg/sources/sheca.json, normalized to lowercase unseparated SHA-1 and ISO dates. Not a full mirror. The listing was read on 2026-11-27; dates and status are publisher claims, not cryptographic findings. LISTED means present in root/intermediate table, not confirmed active. DISUSE means listed in the disuse table, not automatically revoked. A date is the displayed expiration date, not a verified DER date. Historical entries are retained separately by listing identifier. No DER, PEM, downloaded policy PDF or personal certificate is committed.

## Evidence sources and next review

- SHECA policy repository (same page): electronic-signature authentication CPS v1.0, e-government CPS v2.1, event certificate CP/CPS v2.0, remote signing RSP v1.0.0, UniTrust CP v1.6, and historical CPS v3.8.2 are linked. These are document leads, not conclusions about permitted certificate policy OIDs. Consult the relevant version and effective date before assigning any purpose.
- SHECA's UniTrust brand catalog: https://www.imtrust.cn/jishuwendang/dmqmwd/96.html — secondary issuer-controlled catalog, not independent confirmation.
- SATL listing: https://satl.ofd.cn/list — independent-program discovery lead; confirm specific fingerprints, effective dates and document/seal scope. Current retrieval did not expose complete rows/links, so no membership is asserted here.
- Mozilla/CCADB included certificate report: https://ccadb.my.salesforce-sites.com/mozilla/includedcacertificatereport — TLS-specific comparison source, not evidence of document signing or seal authorization.
- SHECA PKI contact is policy@sheca.com, as listed in the repository. Clarify certificate redistribution rights and policy OIDs, particularly historical electronic seal, document signing and seal-maker chains.

## Manual intake

1. Open primary listing directly, locate the named row and use its displayed PEM download action. The primary page did not expose stable direct URLs in the retrieved text; the secondary official UniTrust catalog now provides observed links for 11 selected roots. Do not guess links or use unverified mirrors. Save original bytes outside Git.
2. Record exact download URL, retrieval timestamp, original file SHA-256, publisher listing evidence and any independent SHA-256 evidence in a review note. Explicit sources fetch is available only for embedded observed URLs; the explicit research batch is limited to embedded observed URLs; no arbitrary URLs or archive extraction. Do not use actual user signing certificates.
3. Run sources preview with the row ID and downloaded DER/PEM. It computes DER SHA-256 and compares the legacy published SHA-1. An optional independently obtained SHA-256 can be supplied for comparison; the command cannot verify the independence or authenticity of the supplied value. Mismatch rejects the preview. Preview does not persist.
4. Verify CA classification, subject/issuer, validity, exact DER fingerprint, cryptographic relationships and relevant CP/CPS/OIDs. A same-name or cross-signed certificate must be individually identified. SHA-1 matching is a weak historical cross-check only; it cannot authorize trust.
5. If local research storage is required, use the existing import command with exact public source URL in a local inventory outside Git. Keep status CANDIDATE, redistribution NOT_REVIEWED. Commit only permitted reviewed data through PR after independent evidence review. No anchors are added by this catalog.
6. Record source permission, historical lifecycle and scope-specific decision separately. If permission is unclear, keep only source metadata and fingerprints, not redistributed bytes.

## Open work

- Obtain exact downloadable source bytes and independently corroborate SHA-256, including SM2 and historical certificate variants.
- Determine electronic-signature and seal-maker certificate-policy OIDs and scope from official CPS and relevant program evidence.
- Confirm redistribution permission; no publication of certificate bytes before approval.
- Add SATL and other CA catalogs after this intake pattern is reviewed.

## Acquisition endpoints and independent fingerprint leads

On 2026-11-27 the UniTrust auxiliary catalog exposed 11 download links for existing root listings; these are recorded in pkg/sources/sheca-endpoints.json. All point to the same OSS hostname. The page was the source of the links; the object bytes could not be retrieved in the research environment (binary content unsupported and local DNS unavailable). No actual certificate bytes or verified DER findings are committed.

Third-party SHA-256 claims are recorded for UCA Global G2 Root (Mozilla bug 2088275: https://bugzilla.mozilla.org/show_bug.cgi?id=2088275) and UCA Root SM2 / UniTrust Global Root CA R3 (Huawei SM root list dated 2026-10-30: https://www.huawei.com/en/root-certification-program/root-store/huawei-trusted-sm-root-certificate-20261030). Matching these values does not establish source authenticity or document signing authority. Mozilla's issue records a TLS-only transition and removal of the email trust bit; do not infer document or seal authorization from this hierarchy. Huawei's list scope is SM root store, not electronic seal policy. These are name-matched fingerprint leads until local bytes are checked against both hashes.

```sh
go run ./cmd/trust-registry sources endpoints
mkdir -p "$HOME/sheca-research"
go run ./cmd/trust-registry sources fetch --id uca-sm2 --out "$HOME/sheca-research/uca-sm2.cer" > "$HOME/sheca-research/uca-sm2.json"
go run ./cmd/trust-registry sources audit --id uca-sm2 "$HOME/sheca-research/uca-sm2.cer"
```

Fetch is explicit and HTTPS-only, fixed embedded URLs, no redirects, no environment proxy, bounded 1 MiB response and 30-second request timeout, no compressed responses, no overwrite. It checks published SHA-1 and, if available, the pinned external SHA-256 before saving original bytes locally. For the other eight endpoints an explicit --allow-legacy-only is required. A SHA-1-only match is weak evidence and must remain unreviewed. Output is a JSON report; save it separately. Audit accepts local bytes and never claims retrieval. Download transport uses normal system TLS verification, not a registry trust fallback. Reports retain source hash, actual DER fingerprint, source reference and CA extension/self-signature diagnostics; policy identifiers are the library's legacy ASN.1 OID view, not a complete policy engine. No path validation, revocation or trust authorization. No automatic registry import, no publication or upload. Keep original bytes and report outside Git until redistribution permission and independent review are completed. Crash during local file write can leave an incomplete file; delete and retry after checking.

## Manual GitHub Actions research

After this workflow is merged to the default branch, open Actions → Certificate Research → Run workflow. Default sha256-only attempts only the three endpoints with third-party SHA-256 leads; include-legacy attempts all eleven observed endpoints, with weaker SHA-1-only matches clearly labeled. The CLI equivalent is `trust-registry sources research [--include-legacy]`. The batch uses downloaded bytes only in memory; output is JSON diagnostics, never raw DER/PEM, automatic registry imports, commits, or trust grants. A failed request/hash comparison does not abort the remaining endpoints; partial failure returns nonzero and the report still uploads for seven days. Only explicitly initiated runs make requests; normal CI tests use a synthetic transport. This is not proof of redistribution rights. No actual workflow results are claimed until a completed run is inspected.
