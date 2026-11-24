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
response at RequestResponse. The same namespace records a register read and
creation of an empty Secret at Metadata, without body fields. Fixture-created
writer and reader ServiceAccounts are bound to roles limited to the exact
synthetic record. Kubectl impersonation demonstrates the writer's approved
patch, the reader's successful get, and the reader's denied patch; separate
API audit events record each fixture identity and response code. The fixture
also compares a bounded current snapshot of case-owned records (up to 50, sorted
newest first) with one owned synthetic workload reference, observes it missing, and observes
the gap resolve after its complete record carrying a fixture-only approval
annotation is added. Minimal stable fields are written to
`psa-register-observations.json` when the case runs.

## Adopter guidance

Inventory actual native Pod Security Admission exemptions from the effective
API-server configuration and change records. For each exemption, record which
native dimension applies—username, namespace, or RuntimeClass—plus its exact
value, owner, approval, rationale, and review/expiry. Native PSA does not match
exemptions on Pod labels or ServiceAccounts; a matching exemption skips PSA
enforce, audit, and warn checks for that request.

Assess Gatekeeper, Kyverno, or other admission policies separately. Those
controls can match workload labels and ServiceAccount identity, but their
scope and outcomes must be verified from the actual deployed policy, bindings,
and benign allowed/denied workload requests. Keep those checks distinct from
this register case: a complete register entry and successful fixture RBAC
check do not prove an actual exemption is approved, a separate workload policy
is effective, or a declared compensating control works. Auditable approval
claims in this case are scoped only to the named fixture ServiceAccounts and
the exact synthetic record operations. Capture adopter-specific authorization,
policy, compensating-control, audit delivery, and retention evidence separately.

The fixture checks record shape on create and update. Actual exception
authorizations, ownership and review history, compensating-control
effectiveness, and production audit coverage require separate evidence.

[Kubernetes ValidatingAdmissionPolicy](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/) ·
[Pod Security Admission exemptions](https://v1-36.docs.kubernetes.io/docs/concepts/security/pod-security-admission/) ·
[Kubernetes audit levels](https://v1-36.docs.kubernetes.io/docs/tasks/debug/debug-cluster/audit/)
