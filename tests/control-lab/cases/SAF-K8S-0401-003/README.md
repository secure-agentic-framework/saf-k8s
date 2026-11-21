# SAF-K8S-0401-003 — Aggregated ClusterRole governance

```sh
python3 lab.py test SAF-K8S-0401-003 --docker-context desktop-linux
```

The case uses only its own Kubernetes v1.36.1 RBAC objects and ConfigMaps.
It first establishes a labeled CustomResourceDefinition and an unmatched
aggregate ClusterRole. The CRD contributes no rules, and the independent
consumer cannot read the fixture. Before policy activation, the fixture's
reviewer can dry-run an unapproved metadata update to the contributing
ClusterRole. After activation, validation rejects that update, while the same
reviewer can submit the approved metadata with the contributor rules intact.

The actual aggregation controller reconciles the approved ClusterRole's rule.
A separate consumer bound through a namespace RoleBinding reads the exact
named ConfigMap and receives Forbidden for the other fixture. The policy also
rejects a changed owner and permits an unrelated fixture role update. The
reviewer has ordinary permission to edit the named fixture roles and already
holds their one ConfigMap permission. The consumer receives its validated
grant through the aggregate role. The kind runner deletes all objects.

This illustrates one admitted contributor and exact aggregate selector.
Deployment review still covers all real selectors and contributors, review
authority and approval evidence, and effective permissions in default
admin/edit/view roles used by the cluster.

- [Kubernetes v1.36 aggregated ClusterRoles](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/#aggregated-clusterroles)
- [Kubernetes v1.36 ValidatingAdmissionPolicy](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)
