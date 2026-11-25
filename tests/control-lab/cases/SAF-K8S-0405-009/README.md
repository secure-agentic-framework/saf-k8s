# SAF-K8S-0405-009 Scoped API impersonation

Run by ID on fresh Kind. Authorization reviews ask the real server
whether a synthetic reviewer may use each named fixture identity.
The checks cover users, groups, ServiceAccounts, extras and UIDs. A
single permitted request demonstrates ordinary RBAC under the allowed
read-only identity. The caller's direct request remains denied.

The case limits inputs to its own harmless fixtures. Production approval
records, effective broad grants, constrained impersonation and audit
retention require their own evidence.

- [Kubernetes user impersonation](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/user-impersonation/)
- [Kubernetes authorization](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/authorization/)

## Verify an adopting implementation

Inventory `impersonate` and `bind` grants across direct,
group, wildcard, inherited, and cluster-wide roles. For each approved caller,
review exact user/group/ServiceAccount/extra/UID targets and API groups using
effective authorization checks; prove unrelated identities and resources are
denied. Run one approved harmless delegated request, revoke its grant, confirm
denial, and retain approval plus attributable audit records.
