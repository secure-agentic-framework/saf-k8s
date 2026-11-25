# SAF-K8S-0405-022 Tenant-scoped emergency access

Run by ID on fresh Kind. Two ordinary temporary identities exercise
actual reads of public fixture objects. Removing an extra namespace
grant eliminates the cross-tenant read without replacing the
credential. The intended read and the independent neighbor's read
still work. The test imports the temporary credential helper from
SAF-K8S-0405-020.

- [Kubernetes RBAC](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/)
- [Kubernetes multi-tenancy](https://v1-36.docs.kubernetes.io/docs/concepts/security/multi-tenancy/)

From the SAF-K8S repository root, run `python3 tests/control-lab/lab.py test SAF-K8S-0405-022 --docker-context desktop-linux`.

## Adopter verification

Inventory actual tenant boundaries, emergency issuers, authorized subjects, scoped resources and inheritance, including shared or cluster-wide resources. In an approved exercise, compare the same emergency credential on its approved, neighboring and shared resources. Confirm the expected operation remains available and the equivalent out-of-scope path is refused. Check effective role inheritance, alternate routes, controlled expiry and rollback, and retain correlation to the actual audit actor.
