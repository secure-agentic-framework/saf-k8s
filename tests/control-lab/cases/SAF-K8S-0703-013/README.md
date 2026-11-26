# SAF-K8S-0703-013 — Topology-aware placement and failure-domain spread

From the framework checkout, run the comparison on a fresh Kind cluster.

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0703-013 --docker-context desktop-linux
```

From the lab checkout, invoke `python3 lab.py` with the same arguments.
The native kube-scheduler places a Pod on the synthetic locality-labeled
worker and leaves the missing target pending. With two synthetic failure
domains, the live case compares the unconstrained and exact enforced
maximum-skew behavior. This exercises the Kubernetes placement primitives
with label values supplied by the fixture. Device NUMA alignment and
accelerator fabric performance require their own observations.

## Verify actual locality and failure-domain placement

1. Identify the workload, training roles or serving replicas, actual
   hardware and requested resources, and the required locality and failure
   domains. Verify authoritative label producers, label ownership and what
   happens when labels are absent or stale.
2. Where node-local alignment matters, collect the live kubelet Topology
   Manager policy and scope, applicable CPU and memory options, and device
   plugin version and exported NUMA hints. Verify the resulting CPU and
   device allocation for an eligible Pod and its admission outcome when
   the requested alignment cannot be met in a disposable test pool.
3. Where fabric locality matters, compare inventoried GPU and network
   topology with the actual labels and scheduler decisions. Run an
   approved bounded distributed job and confirm every role's assigned
   device and domain. Compare with an impossible topology request in
   the isolated pool. Measure representative communication performance
   before claiming bandwidth improvement.
4. Verify the live spread selector, domain label, available capacity,
   maximum skew and unsatisfiable action for each governed workload.
   Verify distribution of the actual roles or replicas. In a separately
   approved test environment, compare behavior after loss of a representative
   domain. Capture health, reschedule or checkpoint outcomes and recovery
   time against the workload's availability requirements.

[Kubernetes Topology Manager](https://v1-36.docs.kubernetes.io/docs/tasks/administer-cluster/topology-manager/),
[Kubernetes device plugins](https://v1-36.docs.kubernetes.io/docs/concepts/extend-kubernetes/compute-storage-net/device-plugins/),
[Kubernetes topology spread](https://v1-36.docs.kubernetes.io/docs/concepts/scheduling-eviction/topology-spread-constraints/),
and [one provider fabric topology integration](https://docs.nvidia.com/topograph/v1.1.0/engines/kubernetes/).
