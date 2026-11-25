# SAF-K8S-0401-001 — Effective least-privilege Role bindings

```sh
python3 lab.py test SAF-K8S-0401-001 --docker-context desktop-linux
```

The disposable cluster contains a case-owned service account and three
synthetic ConfigMaps across two namespaces. The broad baseline permits an
unneeded named read, collection listing and a server dry-run metadata patch.
Add the narrow Role while retaining the broad binding to observe that RBAC
grants are additive. Remove the broader binding and replay the requests.

The exact named GET remains permitted, while the unrelated name, other
namespace, collection list, and unneeded patch are forbidden. The patch
uses the named object the identity may read, so the error identifies the
patch authorization decision. The runner deletes the cluster and fixtures.

The original exact allow/deny assertions cover one namespaced ServiceAccount.
The added checks cover selected synthetic group and cluster-wide cases.
Production verification still requires a complete identity inventory,
documented work requirements, admission governance and recurring review.

## Extended checks

`case.py` invokes `extended_checks.py` for the same disposable fixture after
the narrow Role assertions complete. The extension does not
replace or alter the existing exact allow/deny assertions. It adds:

- **Effective group grant:** a named ConfigMap GET changes from `no` to `yes`
  through a synthetic group RoleBinding; deleting that binding returns it to
  `no`, while the direct required GET stays `yes`.
- **ClusterRoleBinding and aggregation:** a child ClusterRole contributes one
  `get` rule for the named ConfigMap to an aggregated ClusterRole. The bound
  synthetic group gets `yes` for that exact name and `no` for another name.
  It also detects `yes` for that name in the second namespace, exposing the
  ClusterRoleBinding's cluster-wide scope; after deleting that binding the
  second-namespace check returns `no` while the required namespace GET stays
  `yes`. The aggregation controller must copy the child rule before checking.
- **Source review and revocation:** `kubectl diff` against
  `least-privilege.yaml` detects an added benign named GET and clears after
  restoring that manifest; impersonated SelfSubjectAccessReviews confirm the
  extra permission's `yes` to `no` transition and the required GET stays `yes`.
- **Admission comparison:** a namespace-label-scoped ValidatingAdmissionPolicy
  rejects a dry-run Role with wildcard verbs/resources and admits a dry-run of
  the approved exact-name Role. The overbroad Role is never bound.

`no` is the expected authorization denial reason: no applicable RBAC rule
grants that exact verb, ConfigMap name and namespace. It is not evidence of an
API object-not-found response. The positive comparison is the required named
GET returning `yes`. The existing `case.py` API request assertions retain their
more specific Forbidden checks.

### Adopter verification

1. Record the approved work for each human role, service account, and
   group. Identify the authorization tuple with subject, resolved groups,
   verb, API group, resource and subresource, resource name, and namespace
   or cluster scope. Retain the approving owner and source revision.
2. Collect the applied Roles, ClusterRoles, RoleBindings, and
   ClusterRoleBindings through an approved inventory export. Resolve role
   aggregations and direct and inherited grants. Compare the inventory with
   the approved provisioning or GitOps source. For a managed service,
   identify which authorization decisions come from customer-managed RBAC
   and which require provider evidence.
3. Confirm the effective API decision for a required tuple and for
   representative unrelated names, namespaces, verbs, and subjects. Use an
   authorized review or an approved test identity. For an external group,
   verify the identity-provider group claim, its Kubernetes mapping, and
   the relevant bindings. In the companion
   [OIDC case](../SAF-K8S-0402-007/README.md), a real test-issued credential
   maps into a narrow group grant, another group receives Forbidden, and
   withdrawing the binding preserves authentication while removing access.
4. Reconcile a case-owned grant in a disposable environment and repeat the
   required and unnecessary requests. Verify that admission applies to the
   intended resource kinds and scope, and confirm that approved templates
   still pass. Retain the before and after configuration, expected and
   observed decisions, and any exception rationale and expiry.
5. Set a review owner and cadence. Record the scope, findings, changes,
   approval or exception disposition, and evidence location for each review.
   The [RBAC audit case](../SAF-K8S-0401-002/README.md) demonstrates a
   scheduled named-access audit and confirmation after remediation. Use the
   deployed identity provider and authorizers for deployment-specific
   decisions.

- [Kubernetes v1.36 RBAC](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/)
- [Kubernetes v1.36 authorization](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/authorization/)
