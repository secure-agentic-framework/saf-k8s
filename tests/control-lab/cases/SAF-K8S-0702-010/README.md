# SAF-K8S-0702-010 — Virtual control-plane isolation and host synchronization

Run from the lab checkout.

```sh
python3 lab.py test SAF-K8S-0702-010 --docker-context desktop-linux
```

From the framework checkout, invoke `python3 tests/control-lab/lab.py`.
The owned host Kubernetes cluster compares its shared cluster-scoped
API state with two separate pinned virtual control planes. Identically
named tenant records retain separate API state. The tenant namespace
does not appear on the host, and the selected tenant subject probes
receive no tested host permission.

Each release explicitly enables the test's ConfigMap synchronization
mode. A tenant-owned inert marker appears once in the correct host
release namespace with the expected source attribution and data.
Deleting the tenant source removes its synchronized host copy. The
example's Kubernetes node and kernel are shared by the virtual clusters.

## Verify adopted tenant isolation

1. Identify the tenant and host authorities, issued kubeconfig identities,
   host privileges, shared infrastructure and worker model. Define the
   threat model and which operations and resources require API, network,
   storage, worker, device or kernel isolation.
2. Compare identical cluster-scoped names across actual tenants and
   independent host access by the governed service and tenant identities.
   Verify the selected approvals, grants, scope and credential lifetime.
3. Inventory the synchronization directions, approved resource kinds,
   transformations, selected names and sync controller privileges. Create
   an approved benign test object, match its exact permitted host or
   tenant copy, check absence from outside scopes, then observe update
   and approved source deletion across the controlled APIs.
4. Exercise any independently required runtime, worker, network, storage
   and accelerator controls, and verify failure and recovery for the
   selected topology. Record what remains shared and evidence for approved
   exceptions and remediation owners.

[vCluster ConfigMap synchronization](https://www.vcluster.com/docs/vcluster/configure/vcluster-yaml/sync/to-host/core/config-maps)
and [vCluster synchronization boundaries](https://www.vcluster.com/docs/vcluster/configure/sync).
