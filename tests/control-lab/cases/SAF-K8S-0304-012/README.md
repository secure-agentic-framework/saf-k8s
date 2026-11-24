# SAF-K8S-0304-012 — Training scratch bounds and ephemeral-storage quotas

Run from the SAF-K8S framework root on a disposable Kind cluster.

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0304-012 --docker-context desktop-linux
```

The case verifies three independent controls on Kubernetes v1.36.1.

1. **Admission** requires a positive size limit for disk-backed `emptyDir`
   and ephemeral-storage requests and limits for regular and init containers.
   A memory-backed scratch request stays outside the sample disk-specific
   policy. The memory-backed probe is a server dry-run before quota is enabled.
2. **ResourceQuota** accounts for the live Pod's declared requests and limits.
   Separate dry-runs show rejection by the aggregate request and limit keys.
3. **Volume accounting and eviction** compares a 1 MiB write with a 3 MiB
   write against the same 2 MiB disk-backed volume limit. The kubelet reports
   filesystem headroom and usage for the named under-limit volume. The 3 MiB
   write finishes and the kubelet then evicts that Pod for the exact named
   volume limit. Both workloads have a 16 MiB aggregate storage limit.
   Node DiskPressure is false before and after the paired test.

The run retains scoped filesystem values, the measured control volume and the
native eviction evidence in `scratch-volume-accounting.json`. The test uses
small bounded writes and observes asynchronous eviction. Namespace quota
accounts for declarations and the kubelet measures volume usage.

## Verify your implementation

- Verify each covered workload and namespace, including init containers,
  declared limits, effective quota, and admitted Pod fields. Treat alternative
  storage separately. Memory-backed `emptyDir` usage counts toward memory.
- Verify the actual kubelet measures the deployed node, image and container
  filesystem configuration where applicable. Compare available bytes and
  inodes, observed Pod or volume usage, and configured limits. Check capacity
  alert delivery and correlate Node DiskPressure, events and Pod status.
- In authorized representative staging, use a bounded below/above comparison
  and retain the exact native reason. A volume-size failure, a Pod aggregate
  storage-limit failure and a node-pressure eviction have distinct evidence.

- [Kubernetes v1.36 local ephemeral storage](https://v1-36.docs.kubernetes.io/docs/concepts/configuration/manage-resources-containers/#local-ephemeral-storage)
- [Kubernetes v1.36 emptyDir](https://v1-36.docs.kubernetes.io/docs/concepts/storage/volumes/#emptydir)
- [Kubernetes v1.36 Resource Quotas](https://v1-36.docs.kubernetes.io/docs/concepts/policy/resource-quotas/)
