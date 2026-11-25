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

## Scheduled recurrence check

The canonical `case.py` entrypoint also creates a disposable CronJob in the
case namespace. It uses the repo's digest-pinned Python fixture image and runs
once per minute with `Forbid`, no retries, and a bounded Job deadline. Its
worker runs as the existing synthetic audited reader. A temporary
ClusterRoleBinding grants only `create selfsubjectaccessreviews.authorization.k8s.io`
for the cluster-scoped reviews. The reader's checked ConfigMap permissions
come from the original bindings and their remediation. The job makes two
fixed, literal benign authorization requests: `get` the named required
ConfigMap, expected allowed, and `get` the named deliberately unneeded
ConfigMap, expected denied. It does not read or mutate either ConfigMap.

The case waits for one genuine CronJob-owned Job to record the original gap
(both named GETs allowed), deletes only the case-owned
`saf-0401-002-unneeded-reader` RoleBinding, then waits for a later scheduled
Job to confirm required allow / unnecessary deny. Each worker emits a
JSON-encoded line with owner, due cadence, disposition, observation time, Job
name, and both decisions. The lab reads the Job logs and scheduled
timestamps and retains the verified ownership, ordering and decisions in
the replay receipt. A valid API response with `status.allowed: false` is an
explicit denial. HTTP/API errors, TLS/network failures, missing or malformed
status, and `evaluationError` fail the Job and cannot count as a denial.
After evidence is captured, the helper deletes its CronJob and temporary
ClusterRole/ClusterRoleBinding so the existing case inventory remains exact.

Native CronJobs have one-minute schedule granularity. Each wait is bounded to
85 seconds, so the two observations take up to 170 seconds plus ordinary case
setup. The first image pull and an unhealthy controller may exceed that bound;
the test then fails with an infrastructure timeout instead of inferring a
permission result. This short recurrence demonstration validates only the
named decisions in the fixture namespace and does not establish scheduled
coverage of other identities, namespaces, or permissions.

For adoption beyond this disposable example, adapt collection permissions, cluster/context selection, namespace coverage,
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
- [CronJob scheduling](https://v1-36.docs.kubernetes.io/docs/concepts/workloads/controllers/cron-jobs/)
- [SubjectAccessReview](https://v1-36.docs.kubernetes.io/docs/reference/kubernetes-api/authorization-resources/subject-access-review-v1/)
