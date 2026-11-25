# SAF-K8S-0401-006 — Separate ML, platform, and security RBAC

```sh
python3 lab.py test SAF-K8S-0401-006 --docker-context desktop-linux
```

Three independent Pods use their own projected ServiceAccount identities
over TLS. Before RoleBindings, each receives HTTP 403 for all three
fixture operations. After binding, the ML identity reads only its model
marker, the platform identity can dry-run patch only its platform marker,
and the security identity reads only its audit marker. Each still receives
403 for the other two operations. A separate bounded positive-control
identity can perform all three. The dry-run patch leaves the resource
unchanged.

The fixture covers named namespaced RBAC rules. Actual identity-provider
group mappings, cluster and operator grants, organizational approval and
review records, and exception governance require deployment evidence.

[Kubernetes RBAC](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/) ·
[Kubernetes ServiceAccounts](https://v1-36.docs.kubernetes.io/docs/concepts/security/service-accounts/)

## Effective separation of duties

The positive split uses three distinct scoped synthetic identities. The same
fixture then links one temporary second-function grant to the existing ML
identity. The native authorizer permits the union of both actions and the
case's explicit conflict check detects that combination. Removing the added
binding restores the expected authorization matrix. Each operation stays
inside the disposable test namespace.

For adoption, use a complete identity and binding inventory and map users,
groups, external identity attributes and service accounts to their effective
functional grants. Reconcile namespaced, cluster-wide and indirect bindings,
including groups shared across assignments. Test selected expected permissions
and incompatible combinations in an approved environment. Require independent
review of proposed overlap, a scope and expiry for approved exceptions, and
evidence that the grant was withdrawn or reviewed.
