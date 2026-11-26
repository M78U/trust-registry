# Data model

Schema version 1 is experimental. DER SHA-256 lowercase hexadecimal is the certificate identity; PEM is transport only. Store original DER at registry/certificates/<fingerprint>.der and metadata separately. Derived fields are generated and must be checked against DER. DN display text is not a canonical identity. Serial is a positive hexadecimal integer; SKI/AKI are hexadecimal octets. Distinguish key algorithm, signature algorithm and CA role; self-issued does not establish root trust. Historical certificates remain available.

Provenance records independently bind source URL, institution/type, retrieval time, original file hash, DER hash, review evidence, reviewer/time, policy basis and redistribution permission. Multiple records per certificate are permitted. A retrieval timestamp is an assertion about retrieval, not proof. No redistribution until permitted.

Policy identifies jurisdiction, purpose, version, anchors and intermediate candidates, with explicit constraints. Trust decisions are append-only, reference certificate, policy, role, status, reason and evidence; distinguish recordedAt from effectiveFrom/effectiveUntil. Resolve conflicts deterministically or reject ambiguous records. Expiration, revocation and policy distrust are distinct.

Snapshot contains schema and registry versions, monotonic sequence, publication/expiry timestamps, file hashes, index, policy/decision versions and authenticated metadata. Strict schema and reference integrity checks precede use.

Initial code and two schemas cover candidate metadata only; policy, decisions, manifest and full persistent layout remain planned.
