# SAF-K8S-0405-022 Tenant-scoped emergency access

Run by ID on fresh Kind. Two ordinary temporary identities exercise
actual reads of public fixture objects. Removing an extra namespace
grant eliminates the cross-tenant read without replacing the
credential. The intended read and the independent neighbor's read
still work. The test imports the temporary credential helper from
SAF-K8S-0405-020.

- [Kubernetes RBAC](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/)
- [Kubernetes multi-tenancy](https://v1-36.docs.kubernetes.io/docs/concepts/security/multi-tenancy/)
