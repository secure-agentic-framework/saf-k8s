# SAF-K8S-0702-024 — Tenant namespace-scoped RBAC boundary enforcement

```sh
python3 lab.py test SAF-K8S-0702-024 --docker-context desktop-linux
```

A disposable Kubernetes v1.36.1 administrator inventories RoleBindings across
all namespaces and ClusterRoleBindings for one synthetic ServiceAccount. The
review first detects a binding in its enrolled namespace and two planted
out-of-scope grants. Each fixture grant is limited to one named ConfigMap read.
The administrator removes the planted grants before any workload starts and
then restores only the enrolled namespace binding.

The nonroot Pod authenticates to the cluster API with its own projected
identity and verifies the API certificate using the projected CA. A
SelfSubjectAccessReview returns a denial for the local fixture before binding
and an approval after binding. The ordinary API GET in the enrolled namespace
returns the expected synthetic marker. A self-review for the separate
namespace denies the same resource permission. Only the enrolled ConfigMap is
retrieved by the workload.

The test covers direct bindings for one ServiceAccount and one resource
permission. Group grants, other resource types and verbs, human identities,
shared-service exceptions, and recurring production reviews require their own
evidence.

- [Kubernetes v1.36 RBAC](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/)
- [Kubernetes v1.36 ServiceAccounts](https://v1-36.docs.kubernetes.io/docs/concepts/security/service-accounts/)
- [Kubernetes v1.36 SelfSubjectAccessReview](https://v1-36.docs.kubernetes.io/docs/reference/kubernetes-api/definitions/self-subject-access-review-v1-authorization/)

## Adopter verification

1. Inventory actual ServiceAccounts, mapped users and groups, direct and
   inherited grants, and each tenant namespace.
2. Reconcile namespaced bindings and cluster-wide grants against the
   approved scope. Include resolved group membership and shared-service
   exceptions.
3. Use authorized access reviews for expected permitted and denied tuples,
   and record evidence for actual local access where appropriate.
4. Retain the reviewed inventory, owner, assigned exceptions, and cadence.
   Recheck after changes to identity sources and authorization policy.
