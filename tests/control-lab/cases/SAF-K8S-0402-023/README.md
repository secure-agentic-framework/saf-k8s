# SAF-K8S-0402-023 supervised TTL supplement

Scratch-only candidate based on the current published 0402-023 case. It retains the original three inventory, exception and retirement assertions, then creates one owned Pod with a projected ServiceAccount token (`audience=https://kubernetes.default.svc`, `expirationSeconds=600`). It reads the synthetic JWT only into subprocess memory, validates `iat`, `exp`, audience and exact issued lifetime, and submits it to TokenReview before and after expiry. No token bytes enter CLI arguments, command logs, receipts or evidence files.

Expected total: **5 checks** (the existing three plus two actual issuance/lifetime and expiry checks). Expected runtime: **about 11–13 minutes** beyond cluster startup: Pod readiness, 600 seconds to expiry, and 65 seconds of expiration margin for API-server JWT clock skew. The original Pod UID is checked after expiry. Metadata observations and the safe timing receipt contain only booleans, requested/issued seconds and UTC timestamps.

This is a proposed supervised local case, not executed or passed. Before adoption, validate exact v1.36.1 TokenReview behavior, expiry skew and projected volume path against the pinned 0402-012 pattern. Do not expand the conclusion to legacy Secret token validity, long-running workload rotation/consumer reload, Kubernetes versions or configuration other than the fixture, cloud/Vault/database exchanges, or production fleet coverage. 0402-012 separately demonstrates expiration of a frozen original token; it does not establish long-running application reload.

Adopter follow-up remains to inventory governed clusters/workloads, effective token issuance limits and provider exchanges; retain only metadata, identity lineage, measured lifetime, exception owner/approval/deadlines, coverage gaps and retirement evidence.

A fresh projection for a separate Pod with the same ServiceAccount and audience confirms that authentication remains available after the original credential expires.
