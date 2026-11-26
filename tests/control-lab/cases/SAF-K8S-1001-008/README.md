# SAF-K8S-1001-008 — Permitted responses to audit findings

Run from the SAF-K8S control-lab root:

```sh
python3 lab.py test SAF-K8S-1001-008 --docker-context desktop-linux
```

The harness creates a disposable Kind cluster using its pinned
`kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5`
image. The case creates no Pods or other workloads. It uses only four synthetic
ConfigMaps, two ServiceAccounts, and namespaced Roles and RoleBindings.

## Decision and enforcement path

`authorization-matrix.json` is an approved **synthetic** response matrix. It
describes permitted investigation, escalation, policy adjustment, access
control modification, and closure verification actions, with synthetic
approver identities and conditions. One fixture decision approves a single
read-only GET of `finding-approved` by the `response-investigator` ServiceAccount.
The approval does not represent a real organization, person, finding, or
production authorization.

The case first attempts that named GET as the responder before a RoleBinding is
present. It records the API-server `SubjectAccessReview` decision and the actual
impersonated request result. A separate `reviewer-peer` retains access to its
own named baseline ConfigMap as a positive peer. The case then validates the
synthetic decision's hash, both authorized actions, approver set, exact subject,
namespace, resource, verb, and approved state; creates a RoleBinding to a Role
limited to `get` on that one ConfigMap;
and repeats the GET. It checks the live Role and RoleBinding readback, confirms
the responder remains unable to read neighboring fixtures, and confirms the
peer's baseline read still succeeds.

The only enforcement outcome exercised is a namespaced, role-scoped ConfigMap
GET. The test uses API-server impersonation from the lab administrator context;
it does not mint or expose workload credentials. The runner retains raw request
outcomes and object/readback data in `raw-response-evidence.json` and
`commands.log`. These contain synthetic metadata only and are designed not to
include secrets.

## Coverage and limits

The case provides live evidence for one Kubernetes authorization decision that
changes after a fixture approval is validated and the corresponding RBAC grant
is installed. The matrix documents sample permitted responses and approval
conditions. It does not prove that an organization approved the matrix or that
any production workflow enforces it.

## Reversible fixture mitigation reference

The sixth check adds a grouped
check for a second exact synthetic finding (`SYN-AUDIT-008-03`). The finding
names one case-owned ServiceAccount, one harmless ConfigMap, and one temporary
RoleBinding granting only `get` on that ConfigMap. The case observes the
pre-existing named access, rejects a decision missing a required approver
without changing the binding, then applies the exact approved response by
deleting only that RoleBinding. It verifies the actor is denied by both an
actual request and SubjectAccessReview while the separate peer and previously
approved read remain allowed.

A distinct synthetic rollback approval restores the exact recorded
RoleBinding, verifies access is restored, then the disposable case deletes the
same binding again and confirms the final mitigated state. The record includes
before, denied, restored, and final observations plus exact binding metadata;
it contains no credentials or real finding data. This demonstrates one
reversible, namespace-scoped access-removal response, not an organizational
approval, production incident, general policy adjustment, or ticket closure.
The expected case count is six. Real severity criteria, approvers, escalation,
response deadlines, evidence retention, and closure remain adopter evidence.

Escalation delivery, policy adjustment, broader access-control changes,
ticketing/workflow integration, actual audit-log sources, change management,
closure/retention procedures, other API resources, external identity systems,
and production Kubernetes environments remain unverified. The case's positive
peer is a separate synthetic identity and ConfigMap, not evidence of deployment
coverage.

## Primary sources

- [NIST SP 800-53 Rev. 5, AU-6(7), “Permitted Actions”](https://doi.org/10.6028/NIST.SP.800-53r5) — specifies permitted actions for system processes, roles, or users associated with audit-record review, analysis, and reporting; the discussion says permitted actions are enforced by the system and include read, write, execute, append, and delete. The control statement in `control.md` is broader than that enhancement, so this case tests only one illustrative read decision.
- [Kubernetes v1.36 RBAC authorization](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/) — documents namespaced Roles and RoleBindings and `resourceNames` restrictions.
- [Kubernetes v1.36 authorization](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/authorization/) — documents authorization review APIs and `kubectl auth can-i` behavior.
- [Kubernetes v1.36 SubjectAccessReview API](https://v1-36.docs.kubernetes.io/docs/reference/kubernetes-api/authorization-resources/subject-access-review-v1/) — documents server-evaluated authorization review status.
