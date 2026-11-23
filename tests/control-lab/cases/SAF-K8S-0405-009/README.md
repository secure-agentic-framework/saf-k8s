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
