# Third-party notices

Trust Registry's original source is MIT-licensed (see [LICENSE](LICENSE)). Third-party components remain subject to their own licenses and copyright notices. This inventory is not a license grant for third-party assets or a production release authorization.

## Reviewed CLI build scope

The following 15 third-party module versions were identified by the operator's `go list -mod=readonly -deps` for `./cmd/trust-registry` and `./cmd/...` in the TUF module on macOS ARM64, using Go 1.26.11 and committed locks at 0b77078beba96d07d33e855999aa5ce14f4d60c9. The operator supplied the local license evidence archive; its 28 unique evidence files matched their SHA-256 inventory. The 19 files below were matched byte-for-byte by Git blob identity to the corresponding version's upstream files (genproto inherits the repository root license). They are preserved unchanged. Classifications describe the reviewed top-level texts, not every nested file.

| Module | Version | Top-level license | Preserved files |
| --- | --- | --- | --- |
| `github.com/emmansun/gmsm` | `v0.45.0` | MIT | [LICENSE](licenses/gmsm/LICENSE) |
| `github.com/santhosh-tekuri/jsonschema/v6` | `v6.0.2` | Apache-2.0 | [LICENSE](licenses/jsonschema-v6/LICENSE) |
| `github.com/cenkalti/backoff/v5` | `v5.0.3` | MIT | [LICENSE](licenses/backoff-v5/LICENSE) |
| `github.com/google/go-containerregistry` | `v0.20.7` | Apache-2.0 | [LICENSE](licenses/go-containerregistry/LICENSE) |
| `github.com/opencontainers/go-digest` | `v1.0.0` | Apache-2.0 (code); CC-BY-SA-4.0 (documentation) | [LICENSE](licenses/go-digest/LICENSE), [LICENSE.docs](licenses/go-digest/LICENSE.docs) |
| `github.com/secure-systems-lab/go-securesystemslib` | `v0.11.0` | MIT | [LICENSE](licenses/go-securesystemslib/LICENSE) |
| `github.com/sigstore/protobuf-specs` | `v0.5.0` | Apache-2.0 | [LICENSE](licenses/sigstore-protobuf-specs/LICENSE), [COPYRIGHT.txt](licenses/sigstore-protobuf-specs/COPYRIGHT.txt) |
| `github.com/sigstore/sigstore` | `v1.10.6` | Apache-2.0 | [LICENSE](licenses/sigstore/LICENSE), [COPYRIGHT.txt](licenses/sigstore/COPYRIGHT.txt) |
| `github.com/theupdateframework/go-tuf/v2` | `v2.4.2` | Apache-2.0 | [LICENSE](licenses/go-tuf-v2/LICENSE), [NOTICE](licenses/go-tuf-v2/NOTICE) |
| `golang.org/x/crypto` | `v0.57.0` | BSD-3-Clause | [LICENSE](licenses/x-crypto/LICENSE) |
| `golang.org/x/sys` | `v0.48.0` | BSD-3-Clause | [LICENSE](licenses/x-sys/LICENSE) |
| `golang.org/x/term` | `v0.46.0` | BSD-3-Clause | [LICENSE](licenses/x-term/LICENSE) |
| `golang.org/x/text` | `v0.42.0` | BSD-3-Clause | [LICENSE](licenses/x-text/LICENSE) |
| `google.golang.org/genproto/googleapis/api` | `v0.0.0-20250825161204-c5933d9347a5` | Apache-2.0 | [LICENSE](licenses/genproto-googleapis-api/LICENSE) |
| `google.golang.org/protobuf` | `v1.36.11` | BSD-3-Clause | [LICENSE](licenses/protobuf-go/LICENSE) |

## Distribution obligations and remaining review

- MIT and BSD-3-Clause: retain the relevant copyright, license conditions and disclaimers in applicable distributions; respect the BSD non-endorsement clause.
- Apache-2.0: supply the license and applicable copyright, attribution and NOTICE text, retain required notices and identify modified upstream files where applicable. Patent and trademark provisions remain applicable.
- The go-digest documentation license is recorded separately. No upstream documentation is intentionally copied into the project by this notice bundle, and its code license is not extended to documentation.
- The Go standard library/toolchain, nested or package-specific licenses, generated or bundled material, source history, brand rights and CA source material require separate review. The module graph also contains dependencies not selected for this CLI build, including test dependencies. This is not clearance for those modules, tests, vendoring, or other build tags/platforms.
- Before distributing binaries (including Homebrew), enumerate the actual package and module dependencies for every target OS/architecture and build configuration, inspect source-level notices and nested licenses, include the applicable Go runtime license and additional required notices, and ship the complete applicable license bundle with the binaries. Do not assume this macOS ARM64 inventory covers Linux or Windows.
- Recheck on dependency or build changes. Retain private evidence and owner review separately. This document does not mark the full license review or public-visibility gate complete.
