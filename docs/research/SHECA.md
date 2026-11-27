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

1. Open primary listing directly, locate the named row and use its displayed PEM download action. No stable direct binary URLs were exposed in the retrieved page text. Do not guess links or use unverified mirrors. Save original bytes outside Git.
2. Record exact download URL, retrieval timestamp, original file SHA-256, publisher listing evidence and any independent SHA-256 evidence in a review note. No automated fetching or archive extraction. Do not use actual user signing certificates.
3. Run sources preview with the row ID and downloaded DER/PEM. It computes DER SHA-256 and compares the legacy published SHA-1. An optional independently obtained SHA-256 can be supplied for comparison; the command cannot verify the independence or authenticity of the supplied value. Mismatch rejects the preview. Preview does not persist.
4. Verify CA classification, subject/issuer, validity, exact DER fingerprint, cryptographic relationships and relevant CP/CPS/OIDs. A same-name or cross-signed certificate must be individually identified. SHA-1 matching is a weak historical cross-check only; it cannot authorize trust.
5. If local research storage is required, use the existing import command with exact public source URL in a local inventory outside Git. Keep status CANDIDATE, redistribution NOT_REVIEWED. Commit only permitted reviewed data through PR after independent evidence review. No anchors are added by this catalog.
6. Record source permission, historical lifecycle and scope-specific decision separately. If permission is unclear, keep only source metadata and fingerprints, not redistributed bytes.

## Open work

- Obtain exact downloadable source bytes and independently corroborate SHA-256, including SM2 and historical certificate variants.
- Determine electronic-signature and seal-maker certificate-policy OIDs and scope from official CPS and relevant program evidence.
- Confirm redistribution permission; no publication of certificate bytes before approval.
- Add SATL and other CA catalogs after this intake pattern is reviewed.
