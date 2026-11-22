# SAF-K8S-0301-005 — Validate PSA exemption register records

```sh
python3 lab.py test SAF-K8S-0301-005 --docker-context desktop-linux
```

An inert custom resource represents an exemption register entry. Kubernetes
admits an incomplete entry before the scoped policy. After policy activation,
it refuses the same entry plus separate attempts to omit or blank each of the
four required declarations. A complete entry persists. Removing its risk
owner is denied and preserves the stored entry, and a complete revision works.

The real API audit backend retains the selected register write request and
response at RequestResponse. The same namespace records an ordinary register
read and creation of an empty Secret at Metadata, without body fields.
The fixture checks record shape on create and update. Actual exception
authorizations, scoped policy enforcement, ownership and review history,
compensating-control effectiveness, and production audit coverage require
separate evidence.

[Kubernetes ValidatingAdmissionPolicy](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/) ·
[Pod Security Admission exemptions](https://v1-36.docs.kubernetes.io/docs/concepts/security/pod-security-admission/) ·
[Kubernetes audit levels](https://v1-36.docs.kubernetes.io/docs/tasks/debug/debug-cluster/audit/)
