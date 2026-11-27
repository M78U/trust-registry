# SATL document-signing research — 2026-11-27

Primary program pages: https://satl.ofd.cn/list and https://satl.ofd.cn/strategy. The program is the Suwell Approved Trust List, a document-signing trust-list initiative, not a government-wide mandatory trust store or TLS root program.

Access limitation: direct retrieval returned a JavaScript-only shell. Search-indexed copies of the official listing and strategy pages supplied selected names and policy context (index crawled approximately two weeks before observation). Therefore the embedded catalog records only seven selected name-level leads from SHECA and GDCA; it is not a live or complete snapshot. No fingerprint, downloaded certificate, membership effective date or current membership is verified.

## Research boundaries

The indexed strategy describes CA qualification evidence, CP/CPS, audit material, a document signature sample with certificate chain, and key-use/extended-key-use requirements. It also describes time-stamping conditions and removal of members. Verify the current policy version, effective dates and exact wording on the program site before using these as policy evidence.

- UCA Root G2 has the same displayed name as the SHECA listing, so record a name-only candidate reference. It is not an identity match.
- UCA Rapid Root must not be conflated with UCA Rapid SM2 Root.
- SHECA SM2 is ambiguous and is not mapped to UCA Root SM2 without exact DER SHA-256.
- GDCA names are follow-up leads for the GDCA issuer catalog; no corresponding DER fingerprints have been established.

Use `trust-registry sources satl` to view these leads offline. Obtain actual program certificates and compare exact DER SHA-256 with issuer bytes, independently review program scope, CP/CPS and redistribution, then record a distinct scoped decision if approved. Program membership, if eventually verified, is only evidence in the Registry's own governance process; no automatic import, trust authorization, seal-maker or timestamping scope inheritance.
