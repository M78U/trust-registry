# Certificate relationship graph

Derived local graph, not a trust store or authenticated snapshot. Every node is identified by DER SHA-256, not name or public key. Cross-signed certificates remain distinct. The graph may contain one ephemeral input certificate; it is not persisted, and only inventory CA candidates are eligible as issuer parents.

Construction validates the entire inventory (canonical metadata, provenance and reference integrity), then checks DER hashes again while building a bounded parsed-certificate view. Exact raw issuer/subject DN or nonempty AKI/SKI equality selects candidates. The shared direct-issuer helper checks raw signatures, DN, identifier conflicts, CA basic constraints, certificate signing key usage and unhandled critical extensions. Both matched and rejected candidate edges are emitted, with reasons. Edges point child to issuer; self-signature is a node property, not a self-loop. Fingerprints and edges are sorted for deterministic export. Graph objects are immutable to callers except exported copies.

Paths walk only MATCHED direct-issuer edges. A verified self-signature is one possible terminal; alternate cross-signing parents are explored independently. NO_MATCHED_ISSUER, CYCLE (last fingerprint repeats an earlier node), and DEPTH_LIMIT are explicit incomplete endpoints. Limits: 2048 nodes, 32 MiB DER bytes retained, 256 candidates per child, 16384 total edges, depth 1–32 nodes, 256 candidate paths, 32768 traversal steps. Cycles may append a repeated endpoint; depth limit stops expansion before additional nodes. Over-cap graph or path enumeration returns an error, not a partial result. The initial inventory validation/index build precedes graph bounds, so it is not a global memory bound for the store. Rebuild on inventory changes; operator-controlled directory only.

```sh
trust-registry graph --registry ./local-registry > graph.json
trust-registry paths --registry ./local-registry --fingerprint HEX
trust-registry paths --registry ./local-registry --certificate signer.cer --max-depth 16
```

No AIA, network, system roots, trust decision or source authentication. No certificate validity time, path length, name constraints, policy/EKU, revocation or full RFC 5280 path validation; exact DER DN matching can miss semantically equivalent encodings. SELF_SIGNATURE_VERIFIED is only signature evidence, not a root classification. The report always has trustStatus NOT_ESTABLISHED. Do not treat any path as usable trust material. Keep ephemeral signer graphs private; public Explorer export must later use an independently reviewed publication projection.

Synthetic tests cover same-name wrong key, multiple cross-signed issuer paths, self-signature, missing issuer, cycle, depth, deterministic output, copy isolation and corrupt inventory. Existing SM2 discovery tests exercise the same direct-issuer helper.
