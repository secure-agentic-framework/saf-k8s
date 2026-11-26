# SAF-K8S-0910-029 Coordinated multi-cluster lifecycle operations

Run by control ID on fresh Kind. The case creates a second independent
cluster and verifies both under an approved coordination record. One
cluster initially refuses the scoped operator and remains unresolved.
After the case installs the intended approval, both clusters show the
fixture Secret version, exact replacement certificate and incident
access decision. Unaffected access remains available.

All bytes and certificates are local fixtures. Assess deployed scope,
issuer trust, custody, policy reconciliation cadence, recovery, and
incident authority independently.

- [Kubernetes Secrets](https://v1-36.docs.kubernetes.io/docs/concepts/configuration/secret/)
- [Kubernetes RBAC](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/)

## Adopter verification

1. Define the federation/member inventory, authoritative coordinator, credential issuer and expected synchronization interval. Preserve the cluster IDs, environment boundary, operator identity, target list and approved policy/revision used for the review.
2. For an approved change or controlled exercise, bind each target operation to exact namespace/resource/name and expected current version. Review effective permissions per member; record one permitted intended operation and a safe denied out-of-scope operation. Do not copy Secret contents into evidence.
3. After execution, independently read each member's result. Record Secret version/resourceVersion and approved change reference; record public certificate fingerprint, issuer, SANs and validity plus a relying-client verification where certificate use is claimed; record the incident decision and an approved authorization result for the affected identity while confirming an unrelated identity remains unaffected.
4. Preserve member-level success, denial, timeout and stale states separately. Verify retries are bounded and idempotent, and that the federation is not reported converged while any required member remains unresolved. Retain timestamped audit/change records and an owner-approved reconciliation decision.
5. Review membership, trust, key custody, certificate policy and incident authority on the organization's schedule and after member, issuer or policy changes. Keep local 3-check fixture results labeled as portable example evidence and attach deployed evidence separately.
