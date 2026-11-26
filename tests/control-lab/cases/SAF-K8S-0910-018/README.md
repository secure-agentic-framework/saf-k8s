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

## Rechecking a later placement

An independent reviewer approves a separate later candidate against a fresh
observation of the same live member and admission policy. The gate initially
finds the candidate eligible. Adding the Audit action to the owned binding
changes its hash while retaining the Deny action. Native server dry-run
confirms that the workload rule still denies the fixed invalid comparator.
The exact previously eligible candidate is then blocked for live policy
identity drift, and the earlier approved workload remains Available.

For adoption, verify authorized source and evidence producers, current
posture and supported versions, applicable accelerator and driver inventory,
time and exception policy, and every effective placement path.
