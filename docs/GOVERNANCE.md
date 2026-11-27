# Governance

All routine code and data changes go from current main to a work branch, through a PR with appropriate validation and review, then merge and automatic branch deletion. Never force-push main. Bootstrap of a completely empty repository is the sole initial commit exception.

Trust anchor changes, suspension, distrust and scope expansion require independent documented evidence and review beyond ordinary code review. If independent review is unavailable, keep the decision unapproved. Verify source authenticity, DER fingerprint, usage authority, redistribution terms and historical updates. Never publish user documents, personal signing certificates, seal images or private keys.

Repository remains private until foundation and security review are complete. Branch protection and automatic branch deletion must be verified in repository settings. M78U-authored code and original technical documentation are covered by MIT (LICENSE); brand and third-party data rights are separate (NOTICE.md) and must be reviewed. Public-source visibility requires the explicit owner-approved gate in OPEN-SOURCE-READINESS.md, separate from website deployment or signed dataset release. Automatic CI is currently disabled by owner request; record manual validation and restore required review/check controls before public release.
