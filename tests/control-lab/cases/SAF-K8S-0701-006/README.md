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

## Verify an adopting retention backend

For every production storage class and retained artifact type in scope:

1. Inventory retained training-data volumes and checkpoint archives, their business owner, retention class, PV/PVC and backend identifiers, and the authoritative record that designates each item as backup information. Separate ephemeral caches and other out-of-scope volumes.
2. Trace every delete or destruction path: Kubernetes API, CSI/controller, storage provider API/console, backup service, and administrative break-glass path. Record which enforcement layer gates each path and who can change or bypass that layer. A PV admission policy alone does not establish that direct backend destruction is protected.
3. Verify two distinct, qualified approvers are authenticated independently and are authorized for the artifact's class. Check that the system binds each approval to the exact immutable artifact identity and intended destruction, rejects self-approval/duplicate votes, and fails closed when either approval is absent, stale, revoked, or for a different artifact. Review the configured expiry/revocation rules; the portable case does not test them.
4. In a non-production environment, perform one approved harmless deletion workflow and negative checks for zero approvals, a repeated vote by one person, an unauthorized vote, a stale approval, and a mismatched artifact identifier. Confirm the backend reports the expected state transition only after the approved request and that a denied request leaves the volume intact.
5. Verify actual backend deletion or sanitization semantics for each storage provider, including snapshots, clones, replicas, and retained copies. Keep this separate from authorization evidence; do not infer secure erasure from Kubernetes PV object removal.
6. Retain sanitized evidence linking artifact identity, approval identities and timestamps, authorization decisions, execution identity, backend result, exception approval and audit event. Review access and policy changes on the organization's defined cadence and after backend, CSI, identity, or retention-policy changes.

The portable five-check case establishes a reference admission/ledger decision on one synthetic Kubernetes object. Provider behavior, real identities, completeness of deletion paths, retention governance, and physical or cryptographic erasure remain adopter evidence.
