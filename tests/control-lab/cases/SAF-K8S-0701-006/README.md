# SAF-K8S-0701-006 — Dual approval of a retained PV deletion

```sh
python3 lab.py test SAF-K8S-0701-006 --docker-context desktop-linux
```

Three separate nonroot Pods use distinct Kubernetes ServiceAccounts.
A scoped ValidatingAdmissionPolicy associates the security and data
reviewers with separate fields on an approval ConfigMap. Its immutable
target reference is the UID of an unbound synthetic Retain PV record.
A separate admission policy checks the bound ledger and executor
identity before the exact PV deletion.

The executor can submit a dry-run before the policy, and the same
request is denied with zero approvals after installation. The security
reviewer receives a targeted denial for the data reviewer's field.
Its ordinary approval is accepted, but a repeat by that reviewer still
leaves the executor blocked. A successful vote by the data reviewer
allows the authorized executor to delete the exact synthetic PV
record. The lab checks both stored approvals and actual object absence.

Actual backend destruction, protection of the approval infrastructure,
approval expiry and revocation, authenticated human approval, platform
coverage, and production audit require their own evidence.

- [Kubernetes v1.36 ValidatingAdmissionPolicy](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)
- [Kubernetes v1.36 RBAC](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/)
- [Kubernetes v1.36 Retain lifecycle](https://v1-36.docs.kubernetes.io/docs/concepts/storage/persistent-volumes/#retain)
