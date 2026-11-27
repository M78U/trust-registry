# Multi-CA research catalog

Observation date: 2026-11-27. Selected research leads only, not a complete CA inventory. A download listing describes a bundle or a name, not a verified DER identity. No direct binary endpoints or automated extraction are inferred from these pages. Five syntactically valid SHA-256 leads are independently published name-associated observations; the scope of each third-party list is preserved. The retrieved Huawei SM list text for GDCA TrustAUTH E1 CA contains 63 hex characters, so that value is intentionally excluded pending independent confirmation; no padding or guessed character. No equivalence to SATL membership, current revocation status, document trust, electronic seal authorization or redistribution rights. All redistribution states remain NOT_REVIEWED. The CFCA Identity CA item refers to the related policy entry and external Microsoft list; the official chain page does not independently identify its exact bytes. BJCA global certificate listing was visible in search results but direct page retrieval timed out, so the root items are marked OFFICIAL_SEARCH_INDEX_ONLY. Other official pages were opened. No actual certificate files downloaded or committed.

## Sources

- CFCA official chain and CP/CPS page: https://www.cfca.com.cn/zhengshuzizhu/
- Microsoft root program report (CFCA Identity CA, document signing scope): https://ccadb.my.salesforce-sites.com/microsoft/includedcacertificatereportformsft
- BJCA official chain page: https://www.bjca.cn/service/down_198.html
- BJCA global CA certificate directory (indexed only): https://repo.bjca.cn/global/cert/
- Mozilla inclusion record for BJCA Global Root CA1: https://bugzilla.mozilla.org/show_bug.cgi?id=1822921
- GDCA official CA certificate directory: https://www.gdca.com.cn/customer_service/knowledge_universe/ca_cq/
- Huawei root and SM root lists: https://www.huawei.com/en/root-certification-program/root-store/huawei-trusted-root-certificate-20261030 and https://www.huawei.com/en/root-certification-program/root-store/huawei-trusted-sm-root-certificate-20261030

## Commands

```sh
trust-registry sources multi-ca
trust-registry sources multi-ca --authority GDCA
trust-registry sources multi-ca-audit --id gdca-gm-sm2-root local.cer
```

The audit requires exactly one local DER/PEM CA certificate, matching published DER SHA-256, exact subject common name and valid basic constraints; reports raw file hash and existing certificate analysis. It refuses bundle listings, missing fingerprints and mismatches. No provenance source receipt is inferred. It does not fetch, save, import, establish a path, evaluate certificate usage or grant trust. Matching a third-party fingerprint is only a research cross-check. The separate SHECA intake workflow remains unchanged. Obtain original source bytes and confirm identity and license before any reviewed import, preserve any original bundle privately and separate only with a reviewed extraction process. Future work: exact per-member bundle extraction/provenance, independently verified acquisition, Explorer integration. Static catalog is embedded; no Cloudflare queries, scans, writes or new bindings. Go tests added but not executed. Manual validation still has no observed recent run; isolated TUF go.sum remains missing. No production release.
