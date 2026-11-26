# Threat model

Assets: certificate bytes and provenance, policy/decision history, release trust root, signing credentials, client accepted-version state, user privacy.

| Threat | Required mitigation |
|---|---|
| Trust poisoning | Separate inventory and anchors, independent source and purpose evidence, PR review, stricter independent review for anchor changes |
| Snapshot tampering | Authenticated manifest, all file hashes, strict schema and cross-reference validation |
| Release key compromise | Separate credentials, offline root/threshold evaluation, rotation and emergency revocation |
| Rollback/freeze | Persist highest accepted sequence, expiry, trusted time assumptions, explicit isolated history mode |
| Purpose confusion | Policy isolation, constraints, no implicit TLS/OS trust |
| Untrusted parsing/resource exhaustion | Bounded input and bundle sizes, no unsafe extraction, fuzzing and malformed-input tests |
| Network discovery / SSRF / privacy | Disabled by default; explicit opt-in, restrict protocols, DNS/IP, redirects, size, timeout; never promote results |
| Malicious source or contributor | Verify official source independently; evidence, review, no execution of data |
| Explorer compromise | Website cannot establish trust; SDK pins independent release root |

No production trust claims until secure distribution and independent review. Initial parser is not a complete security boundary; fuzzing, SM2, full validation and signed updates remain open.
