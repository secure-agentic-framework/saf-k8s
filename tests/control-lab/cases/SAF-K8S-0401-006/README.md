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

## Adopter verification

1. Inventory the user, group, service account, and external identity
   attributes that determine ML, platform, and security assignments. Record
   effective dates and include nested groups and shared attributes.
2. Resolve direct, aggregated, and indirect Kubernetes grants, including
   cluster-wide and operator permissions. Compare each effective subject's
   functional grants with the approved separation and exception policy.
3. Use an approved rehearsal to submit a representative cross-functional
   assignment to the actual change workflow. Retain the rejected unapproved
   decision and the approved limited exception, including independent
   approver authority. Confirm resulting permissions after each decision.
4. Record the exception owner, rationale, compensating controls, expiry,
   and re-review date. Verify the scheduled review withdraws or renews
   the grant under documented authority.
