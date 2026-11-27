# Strict online target reuse

A strict RefreshAndInstall (including explicit coordinator refresh) always performs the existing bounded online TUF metadata update, checks the full root chain, current independent public release credential and optional external checkpoint. When the latest previously installed and historically verified record has the same signed application sequence, exact root chain and target SHA-256, the client verifies its target length and hashes against current authenticated targets metadata and reuses those bytes rather than downloading the target again.

The reused envelope still passes the existing snapshot verification, validity, version and checkpoint checks and installation baseline checks. Same-sequence metadata conflicts are still rejected. A corrupt latest installed record fails closed before networking; it is not treated as a cache miss. New sequences, different roots, absent installations, research mode and download-only Refresh retain the existing target download behavior. No older-record search, additional persistent target cache, new state format, extra local history scan for reuse, conditional HTTP protocol, retry, or cloud storage binding is introduced.

Successful online reports (including the coordinator's install report) include an optional transfer object:

| Field | Meaning |
| --- | --- |
| metadataRequests | Adapter metadata HTTP attempts, including expected root-not-found probes. |
| targetRequests | Adapter target HTTP attempts. |
| metadataBytes | Metadata response body bytes read by the bounded fetcher. |
| targetBytes | Target response body bytes read by the bounded fetcher. |
| reusedTargetBytes | Verified installed target bytes reused instead of downloading. |
| targetSource | NETWORK or INSTALLED_EVIDENCE. |

Counters are application-level, not billing or wire-level metrics: they exclude headers, TLS, transport-internal retries and unread bodies (including non-200 responses). They are returned on successful online refresh only, not on offline load/recovery or failed updates. No telemetry is uploaded. For an unchanged strict installed release, targetRequests and targetBytes are zero, while metadata requests remain necessary; savings depend on actual snapshot size. New releases still need the complete authenticated target. No change to trust policy or release expiry.

Synthetic local TLS tests assert initial/new target download, unchanged-target reuse with metadata requests, exact installed record preservation and corrupt-baseline refusal. Tests are added but not executed in the current Go 1.23.2 environment; required Go 1.26 and dependency lock/manual acceptance remain outstanding.
