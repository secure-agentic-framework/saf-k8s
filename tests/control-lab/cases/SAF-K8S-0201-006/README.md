# SAF-K8S-0201-006 — Node system and kube reserved resource allocations

```sh
python3 lab.py test SAF-K8S-0201-006 --docker-context desktop-linux
```

Two disposable Kind clusters use the same digest-pinned Kubernetes v1.36.1
image and stock eviction settings. The baseline has no explicit reservations.
The second adds `systemReserved` and `kubeReserved`. Their combined settings
reduce advertised Node Allocatable by 60m CPU, 80 MiB memory, and 3 MiB
ephemeral storage. The comparison uses the actual Node API capacity and
allocatable values.

After the baseline cluster is deleted, the reserved node starts two marker
services in separate, test-owned systemd slices. With only Pod enforcement
enabled, both marker slices keep their default CPU weights and unlimited memory.
With the corresponding daemon enforcement fields enabled, kubelet applies each
distinct memory limit and relative CPU weight to the correct cgroup. Both
markers stay in their slices, a new small Pod starts, the kubelet renews its
Node Lease, and the API server responds to readiness checks. The case restores
the initial kubelet settings and removes its marker slices and cluster.

## Apply the control to an adopter environment

- Inventory pools, node roles, versions, runtimes, node shapes and managed
  service boundaries. Collect the effective kubelet configuration or provider
  equivalent for each pool. Compare `systemReserved`, `kubeReserved`,
  eviction thresholds and enforcement settings with the approved profile.
  Retain the redacted export, profile revision and any unsupported fields.
- Measure normal and peak demand from the OS, kubelet, runtime and required
  agents. Include applicable kernel and GPU host-agent demand and growth.
  Record the measurement window, calculations, margins and approval. Compare
  actual Node capacity, allocatable and eviction headroom against the selected
  reservations rather than copying values from the fixture.
- Where using daemon enforcement, verify the cgroup driver and effective
  enforcement keys. Confirm intended daemon PIDs are in the configured
  cgroups. On cgroup v2, inspect `/proc/<pid>/cgroup`, `memory.max`,
  `cpu.weight` and `cpu.max` in the node's cgroup hierarchy. Retain
  redacted placement and settings for each sampled node. A CPU weight is a
  relative share under contention. The portable test uses marker services.
- When operational protection under pressure is required, use measured
  operational data or an approved, bounded exercise on a representative pool.
  Define limits, readiness and daemon-health thresholds, alerts, recovery and
  rollback conditions in advance. Retain the results and recovered state.
- Verify provider-managed settings through versioned documentation and an
  attributable configuration or service report. Record unobservable behavior
  as unverified. Assess GPU device-memory and other device-specific isolation
  separately.

[Node Allocatable documentation](https://v1-36.docs.kubernetes.io/docs/tasks/administer-cluster/reserve-compute-resources/)
and [v1.36.1 kubelet implementation](https://github.com/kubernetes/kubernetes/blob/v1.36.1/pkg/kubelet/cm/node_container_manager_linux.go).
