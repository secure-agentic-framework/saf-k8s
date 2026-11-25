# SAF-K8S-0401-002 — portable RBAC permission audit fixture

This fixture is a synthetic, repeatable example for a human-led RBAC review. It
keeps the original named `get` check for
`saf-0401-002-required-config`, inventories case-labeled RBAC objects, evaluates
an explicit subject/namespace/verb/resource-name matrix with
`SubjectAccessReview`, records one benign excess, reconciles its binding, and
checks that required reads still work.

## Bounded fixture

All identities and data are synthetic. The case owns two namespaces, three
ConfigMaps, two Roles, one ClusterRole, two RoleBindings, and one
ClusterRoleBinding. Every RBAC object carries the case label
`saf-k8s.example/control-case=SAF-K8S-0401-002`. The audited identity is the
synthetic ServiceAccount `system:serviceaccount:saf-0401-002:saf-0401-002-audited-reader`.
The second synthetic user is an unbound negative control.

The intended decision matrix is:

| Subject | Namespace | Named operation | Before reconciliation | After reconciliation |
| --- | --- | --- | --- | --- |
| Audited ServiceAccount | `saf-0401-002` | `get` required ConfigMap | Allow | Allow |
| Audited ServiceAccount | `saf-0401-002-review` | `get` required ConfigMap | Allow | Allow |
| Audited ServiceAccount | `saf-0401-002` | `get` unneeded ConfigMap | Allow; finding | Deny |
| Audited ServiceAccount | `saf-0401-002` | `patch` unneeded ConfigMap | Allow; finding | Deny |
| Audited ServiceAccount | `saf-0401-002` | `patch` required ConfigMap | Deny | Deny |
| Unbound synthetic user | `saf-0401-002` | `get` required ConfigMap | Deny | Deny |

The excess is intentionally limited to `get` and `patch` of one named synthetic
ConfigMap. `patch` appears only as an authorization-review tuple; no patch or
other data mutation is issued. The minimal recorded disposition is to remove
the case-owned `saf-0401-002-unneeded-reader` RoleBinding and retain the
required RoleBinding and cross-namespace ClusterRoleBinding. Because a
ClusterRoleBinding is cluster-wide, its named `get` grant is not restricted to
these two namespaces; the matrix demonstrates two representative namespace
decisions only. An adopter whose intent is namespace-limited should use
namespace RoleBindings and check every in-scope namespace before adopting that
binding pattern.

## Repeatable adopter workflow

1. Label the exact objects included in the review and record which namespaces,
   subjects, resources, names, and verbs are in scope. This fixture's inventory
   is deliberately limited to its unique case label and two namespaces.
2. Collect Roles and RoleBindings in each in-scope namespace, and ClusterRoles
   and ClusterRoleBindings cluster-wide. Preserve object names, rules, subjects,
   and `roleRef` in the review evidence. Here, the fixture checks the four
   expected inventories and validates each case-owned binding/reference.
3. Define expected decisions before running the audit. Evaluate each explicit
   tuple using API-server authorization review for the named user, groups,
   namespace, verb, API group, resource, and resource name. The RBAC object
   inventory is input evidence, not proof of effective access: grants combine
   additively and other bindings or authorization mechanisms can affect a
   decision.
4. Record a finding with its excess permission, intended access, owner, and
   minimal remediation. This fixture records only a synthetic decision and
   removes only its own excess RoleBinding.
5. Repeat the same matrix after reconciliation. Require the excess decisions
   to be denied and required decisions to remain allowed. Preserve collected
   objects, matrix results, decision, and resulting inventory together.

This is example code for a disposable environment, not a production scanner.
Adapt collection permissions, cluster/context selection, namespace coverage,
identity/group resolution, review authorization, audit scheduling, approvals,
evidence retention, and change tracking to the adopter's environment. Do not
infer coverage beyond the exact selected objects and tested decision matrix.

## Dynamic Resource Allocation

The version-selected case also checks fixed, synthetic SubjectAccessReview
tuples for ResourceClaim status and independent binding and driver permissions.
See [DRA authorization evidence](dra-notes.md) for the exact decision matrix and
its scope. The fixture exercise covers authorization decisions for the declared
operations. Review the actual operator and driver configuration when adopting
the control.

- [Kubernetes RBAC](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/)
- [SubjectAccessReview](https://v1-36.docs.kubernetes.io/docs/reference/kubernetes-api/authorization-resources/subject-access-review-v1/)
