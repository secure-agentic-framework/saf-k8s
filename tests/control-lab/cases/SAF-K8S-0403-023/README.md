# SAF-K8S-0403-023 Credential grant drift

Run `python3 lab.py test SAF-K8S-0403-023` using its verified revision. A
disposable API server captures narrowly filtered metadata events for a
fixture workload. Actual SelfSubjectAccessReview decisions are compared
with approved resource policy, an explicitly allowed standby resource,
and observed use. A changed grant is detected, then removed.

Missing telemetry leaves usage unknown while the independent grant
comparison still detects drift. Cloud IAM, other providers, real policy
evidence and ongoing review remain separate obligations.

- [Kubernetes auditing](https://v1-36.docs.kubernetes.io/docs/tasks/debug/debug-cluster/audit/)
- [Kubernetes authorization](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/authorization/)

From the SAF-K8S repository root, run `python3 tests/control-lab/lab.py test SAF-K8S-0403-023 --docker-context desktop-linux`.

## Adopter verification

Inventory the governed issuers and consumers. Snapshot effective privileges, actor binding, expected use, approved exceptions and their deadlines. In a reviewed evidence window, correlate representative allowed and denied operations and a narrowly scoped permission change to the corresponding workload. Verify separate owner decisions for unapproved privileges and candidates for retirement, and preserve an unknown state for uncovered sources. Retain effective before/after authorization decisions and the owner review.
