# SAF-K8S-0205-009 Service proxy API rights and host boundaries

The Kind fixture compares actual requests made as the active kube-proxy API
identity before, during and after a narrow grant to an owned ConfigMap.
Removing that grant denies the extra read while Service and EndpointSlice
list and watch calls continue. The case separately identifies the actual
kube-proxy process, collects capability and sysctl mount observations, and
proves its ClusterIP still returns the owned marker.

```sh
python3 lab.py test SAF-K8S-0205-009 --docker-context desktop-linux
```

The companion [patched conntrack test](README.conntrack.md) verifies a restricted
Kubernetes v1.36.6 profile with effective NET_ADMIN only, read-only
`/proc/sys`, preserved conntrack capacity, and a working Service after restart.
Its local build and platform prerequisites apply to that separate case.

## Verify an active Service path

1. Identify the implementation, version, mode, API identity, node process and
   provider owner for each Service path. Inventory Kubernetes and provider
   rights and compare required list/watch actions with denies for unnecessary
   operations. Include inherited and aggregated authorization where used.
2. Compare requested and effective host or process privileges, capabilities,
   interfaces, mounts and sysctls. Read the pinned version's configuration
   reference and patch notes for each changed setting. Retain effective
   process state and its association with the running proxy and target node.
3. In a matching disposable profile, exercise approved marker paths and
   scoped negative cases before and after each change or restart. Validate
   actual required forwarding and relevant load, resource or protocol limits.
4. Use equivalent provider evidence for managed or replacement boundaries.
   Test the CNI's workload policy separately. Record owners, exceptions and
   triggers to recheck after changes in mode, version, or operating profile.

- [Kubernetes v1.36 kube-proxy configuration](https://v1-36.docs.kubernetes.io/docs/reference/config-api/kube-proxy-config.v1alpha1/)
- [Kubernetes v1.36 RBAC](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/)
- [Kubernetes v1.36 conntrack preservation change](https://github.com/kubernetes/kubernetes/pull/142199)
