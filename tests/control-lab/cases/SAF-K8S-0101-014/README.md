# SAF-K8S-0101-014 — API server authorization mode baseline

Run against the pinned Kubernetes v1.36.1 kind cluster.

```sh
python3 lab.py test SAF-K8S-0101-014
```

The case inspects the live kubeadm API server mirror Pod for the effective
authorization-mode flag. It verifies that the running chain includes Node
and RBAC and excludes ABAC and AlwaysAllow. Two prohibited example chains
are evaluated as static inputs and never started.

A case administrator impersonates two fixture identities through the
Kubernetes API. The live requests exercise authorization for those usernames
and groups without copying client credentials.

- A synthetic service account gets Forbidden when it requests an existing
  ConfigMap. Adding a namespace Role and RoleBinding for that exact object and
  verb makes the same request succeed. Reading a neighboring object and
  listing ConfigMaps remain forbidden.
- The kubelet identity gets Forbidden for a ConfigMap without a workload
  reference. After a ready Pod assigned to that node mounts the ConfigMap,
  the same request succeeds. A neighboring unreferenced ConfigMap remains
  forbidden.

Kubernetes also supports an ordered structured AuthorizationConfiguration.
The two API server configuration flags are mutually exclusive. When using
the structured form, assess the effective file on each replica. Hosted
settings and replica-level conformance require separate evidence.

- [Kubernetes v1.36 authorization](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/authorization/)
- [Kubernetes v1.36 kube-apiserver flags](https://v1-36.docs.kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/)
- [Kubernetes v1.36 Node authorization](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/node/)
- [Kubernetes v1.36 RBAC](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/)

## Adopter verification

1. Record the Kubernetes and provider versions and each covered API server.
   Retain the approved baseline and relevant source revision, including
   the owner and rationale for any additional approved authorizer.
2. Identify the effective configuration form on every replica. Inspect
   the actual arguments for flag-based authorization. Resolve and parse
   the mounted file for structured authorization and verify its deployed
   hash and reload history. Confirm Node and RBAC appear in the effective
   ordered chain and exclude ABAC and AlwaysAllow. The
   [AlwaysAllow prohibition case](../SAF-K8S-0101-019/README.md) demonstrates
   the approved Node and RBAC chain loaded from a structured file.
3. If the chain includes an approved external authorizer, record its exact
   order, reachable and trusted endpoint, matching conditions, timeout,
   cache and failure policies, and request and identity scope. Review
   representative Allow, Deny and NoOpinion outcomes. Determine when later
   authorizers will be reached. See the
   [authorization webhook trust case](../SAF-K8S-0101-015/README.md) for
   representative endpoint evidence.
4. Use approved read-only authorization comparisons or disposable workload
   requests to corroborate expected named allows and denials. Retain the
   identity and exact request attributes, result, release and timestamp.
   For a managed service, record which settings the customer can inspect
   and collect provider evidence scoped to the deployed product. Mark an
   undisclosed authorizer or unevidenced decision scope unverified.
5. Reconcile the effective chain after upgrades, configuration reloads and
   replica replacement. Preserve approved exceptions, expiry, rollback
   references, and change and review ownership.

- [Kubernetes v1.36 structured API server configuration](https://v1-36.docs.kubernetes.io/docs/reference/config-api/apiserver-config.v1/)
- [Kubernetes v1.36 Webhook authorization](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/webhook/)
