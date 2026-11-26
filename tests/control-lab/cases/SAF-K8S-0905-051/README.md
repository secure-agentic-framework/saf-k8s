# SAF-K8S-0905-051 — Bind the reviewer and artifact in promotion audit

Run `python3 tests/control-lab/lab.py test SAF-K8S-0905-051 --docker-context desktop-linux` from the framework checkout.

The case compares audit-disabled and audit-enabled disposable clusters. Four checks show an exact fixed approval write without audit, the scoped native ServiceAccount approval event with audit enabled, a digest readback from the immutable fixture artifact, and a native OIDC reviewer's authorized write and audit association. The metadata-only event contains the authenticated actor, successful operation, ordered server timestamps and the approval object name, which encodes the full artifact SHA-256. Separate readback confirms the fixed decision, reviewer and digest. The fixture uses only synthetic identity and data and retains stable predicates. See SAF-K8S-0905-050 for the separate promotion authorization check.

## Verify an adopted promotion audit trail

1. Inventory each approval and promotion path, its identity authority, effective reviewer authorization, audit sink and retention policy. Verify the recorded actor comes from authenticated identity and remains attributable through any broker or controller that makes a later API write.
2. Follow an approved test release from the recorded decision and authoritative timestamp through the exact immutable model digest to the promotion and consumer. Confirm wrong users, missing records, and mismatched or stale approvals cannot be mistaken for successful authorized promotions.
3. If a metadata-only audit design is used, prove the actor and digest binding can be independently joined to the protected decision record. If an audit policy stores additional fields, minimize collection and verify that secrets and model payloads are excluded.
4. Retrieve the record from the governed audit destination across a later release or normal rollover. Verify retention, time synchronization, access and integrity procedures and review ownership. Record any paths with missing coverage.

- [Kubernetes audit policy and events](https://v1-36.docs.kubernetes.io/docs/tasks/debug/debug-cluster/audit/)
- [Kubernetes authentication](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/authentication/)
