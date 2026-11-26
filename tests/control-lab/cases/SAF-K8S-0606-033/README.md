# SAF-K8S-0606-033 — Require the approved GitOps deployment path

Run from the framework checkout.

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0606-033 --docker-context desktop-linux
```

This case uses a fresh Kubernetes v1.36.1 Kind cluster, one governed namespace,
and a pinned Argo CD v3.6.1 install. It makes a deterministic fixture Git
commit for an inert Deployment. The actual Argo application controller
reconciles the exact commit, and Kubernetes observes the authorized workload.

The fixture's restricted operator is denied by RBAC. A separate scoped
identity can submit a harmless server-side dry-run CREATE before the policy
is active. With the policy active, Kubernetes denies its CREATE, UPDATE, and
DELETE dry runs. The update names the observed resourceVersion, the delete
sends UID and resourceVersion preconditions, and both leave the existing
zero-replica target unchanged. A local metadata audit policy records selected
request identities, operations, and response status.

## Verify an adopting deployment

1. Inventory the resources, namespaces, API verbs, and paths where direct
   production changes must be restricted. Capture the GitOps version,
   repositories, protected revisions, and effective reconciliation identity.
2. Compare direct users and automation with the reconciler's effective
   permissions. Verify admission registration, policy revision, selectors,
   every affected resource and subresource, and the approved treatment of
   administrative and emergency identities. Review emergency governance
   under SAF-K8S-0606-034.
3. In an authorized nonproduction equivalent, run positive and negative
   comparisons against an inert resource for each covered change path.
   Compare the protected commit with the reconciled object hash. Record the
   authoritative identity and leave the harmless denied target unchanged.
4. In the actual audit pipeline, correlate reconciler and refused requests
   to the expected namespace, operation and response. Verify retention,
   restricted access, and enrollment without storing sensitive payloads.
5. Retain approvals, reconciliation status, observed revision, expected
   deployment coverage, and the owner and expiry of each exception.

- [Kubernetes v1.36 ValidatingAdmissionPolicy](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)
- [Kubernetes v1.36 auditing](https://v1-36.docs.kubernetes.io/docs/tasks/debug/debug-cluster/audit/)
