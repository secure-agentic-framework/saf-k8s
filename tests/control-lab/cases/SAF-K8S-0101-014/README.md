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
