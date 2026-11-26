# SAF-K8S-0401-002 — Verify deployed authorization and applicability

The published 0401-002 reference has 50 matching checks at revision
`7fb949b1cbcce8104e21d9e71b5d905740152a6a`, replayed on separate disposable
Kind v1.36.1 clusters. It demonstrates a bounded RBAC inventory and named
SubjectAccessReview matrix, an actual one-minute CronJob checking two fixed
ConfigMap decisions around a case-owned binding removal, 44 synthetic DRA
authorization decisions, and offline analysis of two inert unbound rule
definitions. It does not establish actual cluster inventory, organizational
approval, provider authorizer behavior, or live DRA component requests.

Use the following steps to verify one deployed cluster without changing its
objects. Repeat them for each governed cluster and relevant identity class.

## 1. Record the effective authorizer configuration

Kubernetes checks configured authorizers in order; an earlier authorizer may
allow or deny before a later one is consulted. `kubectl auth can-i` queries the
API server's effective decision through `SelfSubjectAccessReview`, so its
result is independent of whether RBAC, Node, Webhook, or another supported
authorizer is active. It does not show which authorizer made the decision.
The authorization mode is control-plane configuration and is not reliably
available from ordinary workload API objects.

For a self-managed kubeadm control plane, inspect only the API-server
configuration arguments on each control-plane node:

```sh
sudo grep -nE -- '--authorization-mode|--authorization-config|--authorization-webhook|--enable-admission-plugins' \
  /etc/kubernetes/manifests/kube-apiserver.yaml
```

If `--authorization-config` is set, have the control-plane owner review the
referenced `AuthorizationConfiguration` and report the ordered authorizer
types, names, webhook `failurePolicy`, timeout/cache settings, and reviewed
file version or digest. Do not copy embedded credentials or webhook kubeconfig
contents into the audit record. If command-line modes are used, record the
exact ordered `--authorization-mode` value. If the control plane is provider
managed, use its supported control-plane configuration evidence; do not infer
`RBAC`-only from the absence of visible API-server Pods or manifests. If the
effective chain cannot be confirmed, record it as unknown.

Classify only modes actually configured:

- **RBAC:** inventory Roles, RoleBindings, ClusterRoles, ClusterRoleBindings,
  aggregated-role labels and subjects across the approved cluster scope.
- **Node:** include kubelet identities and their node-to-Pod/volume relationships;
  separately verify the `NodeRestriction` admission plugin. NodeRestriction is
  admission, not another authorizer.
- **Webhook:** document the configured reviewer endpoint, trust and failure
  policy from the protected control-plane configuration. Do not probe a remote
  webhook directly; the normal API access-review command below exercises the
  effective chain.
- **ABAC:** if enabled, include the active policy source/version in the review.
  Do not assume an old policy is absent because RBAC objects look complete.
- **AlwaysAllow / AlwaysDeny:** record if present as a control-plane finding;
  do not enable either mode or use it as an audit test. Kubernetes warns that
  AlwaysAllow bypasses authorization.
- **Provider or organization-wide authorization:** include it only when the
  effective control-plane configuration or provider documentation places it in
  this API request path. Record its actual identity and decision evidence.

Admission policies are evaluated after authorization. Do not count an
admission allow/deny as an authorization decision.

## 2. Confirm the exact authenticated principals

Use a pre-existing context for each real reviewer, service account, or
controller identity under review. Do not print kubeconfig credentials. Set
context names, then ask the API server for the authenticated username and
groups:

```sh
AUDITED_CONTEXT='replace-with-context-for-the-audited-identity'
UNBOUND_CONTEXT='replace-with-context-for-the-unbound-control'

kubectl --context "$AUDITED_CONTEXT" auth whoami \
  -o 'jsonpath={.status.userInfo.username}{"\n"}{range .status.userInfo.groups[*]}{.}{"\n"}{end}'

kubectl --context "$UNBOUND_CONTEXT" auth whoami \
  -o 'jsonpath={.status.userInfo.username}{"\n"}{range .status.userInfo.groups[*]}{.}{"\n"}{end}'
```

Compare the result to the identity and group membership approved by the
organization's identity owner. Repeat for distinct identities used by
operators, controllers, service accounts, and human reviewers. If the context
cannot authenticate or `whoami` is not authorized, that is an unavailable
observation, not a deny decision. Avoid adding impersonation grants for the
audit. `--as` is only appropriate when the caller already has approved
impersonation authority and the review records that fact.

## 3. Run a named read-only access matrix

Select a harmless, non-sensitive ConfigMap already approved for this review
and record the exact expected access before running the commands. Set these
values to the deployed context names, namespaces, and ConfigMap names. Set the
cross-namespace expectation from the approved policy; the published fixture's
ClusterRoleBinding makes it `yes`, but namespace-scoped policy may require
`no`.

```bash
HOME_NAMESPACE='replace-with-reviewed-namespace'
CROSS_NAMESPACE='replace-with-second-reviewed-namespace'
REQUIRED_NAME='replace-with-approved-marker-configmap'
UNNEEDED_NAME='replace-with-reviewed-unneeded-configmap'
CROSS_NAMESPACE_EXPECTED='yes' # Choose yes or no from the approved policy matrix.
set -euo pipefail

check_can_i() {
  context=$1 namespace=$2 verb=$3 name=$4 expected=$5
  if output=$(kubectl --context "$context" auth can-i --quiet "$verb" \
    "configmaps/$name" --namespace "$namespace" 2>&1); then
    [ -z "$output" ] || { printf 'ERROR: unexpected output: %s\n' "$output" >&2; return 2; }
    actual=yes
  else
    status=$?
    if [ "$status" -eq 1 ] && [ -z "$output" ]; then
      actual=no
    else
      printf 'ERROR: access review request failed for %s %s configmaps/%s in %s\n' \
        "$context" "$verb" "$name" "$namespace" >&2
      return 2
    fi
  fi
  case "$expected" in
    yes|no) ;;
    *) printf 'ERROR: expected value must be yes or no\n' >&2; return 2 ;;
  esac
  printf '%s\t%s\t%s\tconfigmaps/%s\t%s\n' \
    "$context" "$namespace" "$verb" "$name" "$actual"
  [ "$actual" = "$expected" ]
}

check_can_i "$AUDITED_CONTEXT" "$HOME_NAMESPACE" get "$REQUIRED_NAME" yes
check_can_i "$AUDITED_CONTEXT" "$CROSS_NAMESPACE" get "$REQUIRED_NAME" "$CROSS_NAMESPACE_EXPECTED"
check_can_i "$AUDITED_CONTEXT" "$HOME_NAMESPACE" get "$UNNEEDED_NAME" no
check_can_i "$AUDITED_CONTEXT" "$HOME_NAMESPACE" patch "$UNNEEDED_NAME" no
check_can_i "$AUDITED_CONTEXT" "$HOME_NAMESPACE" patch "$REQUIRED_NAME" no
check_can_i "$UNBOUND_CONTEXT" "$HOME_NAMESPACE" get "$REQUIRED_NAME" no

kubectl --context "$AUDITED_CONTEXT" --namespace "$HOME_NAMESPACE" \
  get configmap "$REQUIRED_NAME" -o name
```

The script prints one tab-separated `yes`/`no` result per tuple. With
`--quiet`, kubectl returns status 0 for allow and status 1 for deny without
printing a result; non-empty command output is treated as an error, not as a
decision. These checks issue SelfSubjectAccessReviews and one metadata-only
GET for the approved marker. They do not issue a patch, read ConfigMap data,
or create a test permission. If a `ClusterRoleBinding` is intentional, test
representative namespaces and confirm that its cluster-wide reach is approved.
If the expected policy is namespace-only, use namespace RoleBindings and test
the intended namespace boundary.

Repeat the matrix for every in-scope identity and named resource tuple, not
just the two contexts above. Compare API decisions with the effective role
inventory and with approved least-privilege intent. A discrepancy is a finding
for review; do not activate an unauthorized grant to test it.

## 4. Apply conditional DRA checks

DRA checks apply only where the cluster actually deploys a DRA scheduler,
allocation controller, or driver. Determine that applicability from the
cluster's enabled APIs, installed components, and workload configuration; API
availability alone does not mean a driver is deployed. For each actual writer,
record its workload owner, namespace, ServiceAccount, driver name, node
association model, exact API group/resource/subresource/verb, and the source
code or audit evidence that shows the request tuple. Then compare those
identities and tuples to the effective grants.

The companion's 44 DRA reviews evaluate synthetic `resourceclaims/status`,
`resourceclaims/binding`, and `resourceclaims/driver` tuples, including
node-aware verbs and wrong-driver denials. They do not create claims, write
status, identify a live node, or prove that an installed component makes the
same request. Keep deployed component identity and request-construction proof
as separate adopter evidence. If no DRA component is deployed, record
“not applicable” with inventory and owner evidence.

## 5. Retain accountable review evidence

For each cluster and review period, retain the reviewed control-plane
configuration source/version, cluster/context inventory, actual principal and
groups, exact read-only tuple and `yes`/`no` result, reviewer, approval,
finding owner, remediation reference, recheck result, exceptions and expiry,
scheduled-run status, and retention location. Protect identity inventories
according to organizational policy; never retain bearer tokens, private keys,
full kubeconfigs, or unrelated resource data. The fixture's one-minute CronJob
proves a recurrence path for two fixed synthetic ConfigMap requests, not
coverage of the adopter's full estate or its approval and evidence-retention
workflow.

## Applicability and sources

- Kubernetes RBAC inventory, effective API authorization, and a recurring
  decision audit apply to clusters in the declared control scope.
- Node, Webhook, ABAC, and provider-specific checks apply only when that
  authorizer is actually configured in the API-server chain.
- DRA status/binding/driver review applies only where those components are
  deployed; the fixture's synthetic DRA tuples remain reference evidence.
- Human approval, finding ownership, exception governance, cluster coverage,
  and durable evidence retention remain organization-specific.

Versioned upstream references:

- [Kubernetes v1.36 authorization and authorizer ordering](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/authorization/)
- [Kubernetes v1.36 RBAC](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/)
- [Kubernetes v1.36 ABAC](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/abac/)
- [Kubernetes v1.36 Node authorization](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/node/)
- [Kubernetes v1.36 Webhook authorization](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/webhook/)
- [Kubernetes v1.36 `kubectl auth whoami`](https://v1-36.docs.kubernetes.io/docs/reference/kubectl/generated/kubectl_auth/kubectl_auth_whoami/)
- [Kubernetes v1.36 `kubectl auth can-i`](https://v1-36.docs.kubernetes.io/docs/reference/kubectl/generated/kubectl_auth/kubectl_auth_can-i/)
- [Kubernetes v1.36 SubjectAccessReview API](https://v1-36.docs.kubernetes.io/docs/reference/kubernetes-api/authorization-resources/subject-access-review-v1/)
- [Kubernetes v1.36 Dynamic Resource Allocation hardening](https://v1-36.docs.kubernetes.io/docs/concepts/security/hardening-guide/dynamic-resource-allocation/)
