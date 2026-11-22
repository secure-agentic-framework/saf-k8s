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

This test covers one namespaced workload identity. Production verification
still requires effective group and cluster-wide bindings, role aggregation,
documented work requirements, admission governance and recurring review.

- [Kubernetes v1.36 RBAC](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/)
- [Kubernetes v1.36 authorization](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/authorization/)
