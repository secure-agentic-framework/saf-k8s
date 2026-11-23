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
