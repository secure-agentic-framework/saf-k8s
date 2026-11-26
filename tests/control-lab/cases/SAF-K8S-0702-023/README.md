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

## Verify an adopting virtual-cluster deployment

For each deployed virtual-cluster product/version and each supported host configuration:

1. Inventory tenant control planes, host clusters, API endpoints, identity issuers, synchronized object kinds, host groups, administrative principals, and documented exceptions. Record the host/tenant version pair and the boundary each mechanism is intended to provide.
2. Authenticate using the real enrolled identities for two approved tenants. In a controlled staging tenant, create harmless same-named ConfigMaps and a harmless tenant-scoped custom resource with distinct non-sensitive markers. Read each through its intended tenant API and confirm the other tenant's API returns no cross-tenant object. Verify the host API does not unexpectedly serve tenant-only API kinds or objects. Keep object names and outcomes, not marker contents, in retained evidence.
3. Resolve each tenant identity and its groups against effective host RoleBindings and ClusterRoleBindings, including grants inherited through groups and provider-specific authorization outside Kubernetes RBAC. Confirm only documented host access is available. Use authorized read-only review and non-destructive authorization checks; do not access another tenant's data.
4. Review the product's host synchronization configuration and runtime isolation claims against the actual release, node/kernel sharing, admission, network and storage configuration. Treat synchronization filters as separate from authorization and do not infer node, kernel, or storage isolation from separate API endpoints.
5. Re-run the approved identity and boundary checks after identity, role-binding, vCluster version/configuration, host synchronization, or policy changes, and on the organization's stated review cadence. Record reviewer, time, exact scope, exception approval/expiry, allow/deny outcomes, and remediation links. Preserve prior sanitized records so drift is visible.
