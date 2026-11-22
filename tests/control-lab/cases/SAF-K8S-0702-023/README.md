# SAF-K8S-0702-023 — Virtual cluster tenant isolation validation and host access review

```sh
python3 lab.py test SAF-K8S-0702-023 --docker-context desktop-linux
```

The disposable kind host runs Kubernetes v1.36.1 and two vCluster 0.37.7
control planes. Helm uses the pinned chart archive and pinned container
images. The runner connects to each tenant API over a separate verified
loopback TLS connection using that tenant's fixture credentials.

- Each tenant creates the same namespaced ConfigMap and custom resource names
  in its own API with distinct markers. Two reads per object and tenant must
  preserve the expected markers. Both tenants serve the fixture CRD and the
  host API returns `NotFound` for that CRD before and after creation.
- A host administrator plants one limited read binding for a synthetic User.
  A read-only inventory of Roles, RoleBindings, ClusterRoles and
  ClusterRoleBindings must resolve the exact binding and named resource rule.
  After removal, a second inventory must report no direct match for either
  synthetic User. That inventory retains the configured group grants.

The two observations cover an API boundary on a single shared host and
kernel. Actual authenticated tenant membership, effective host permissions
including non-RBAC authorization, host synchronization and runtime
isolation, and repeated reviews in the deployed environment require
separate evidence.

- [Kubernetes v1.36 RBAC](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/)
- [vCluster tenant isolation](https://www.vcluster.com/docs/vcluster/overview/isolation)
- [vCluster synchronization to a host](https://www.vcluster.com/docs/vcluster/configure/vcluster-yaml/sync/to-host)
