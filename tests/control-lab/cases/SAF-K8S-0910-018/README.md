# SAF-K8S-0910-018 posture-aware placement

Run `python3 lab.py test SAF-K8S-0910-018` from the lab directory.

Two separately owned Kubernetes API servers initially accept harmless
workload placement. The test then measures node readiness and each
member's native admission decision in server-side dry run. The placement
gate requires the exact live member, policy, candidate and scoped reviewer
approval. It rejects missing, stale, mismatched and insufficient posture
before acting. A workload becomes available on the independently reviewed
member. Each actor has separate rights for observation, approval or
placement in the fixture.

The demonstration covers a native security check and node health for one
fixture workload. Production trust feeds, orchestration paths and cluster
coverage need separate evidence.

- [Kubernetes v1.36 Validating Admission Policy](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)
- [Kubernetes v1.36 Node status](https://v1-36.docs.kubernetes.io/docs/reference/node/node-status/)
