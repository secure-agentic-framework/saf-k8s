# SAF-K8S-0703-010 — Host resource isolation

From the framework checkout, run the disposable cgroup and CPU Manager
comparison.

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0703-010 --docker-context desktop-linux
```

From the lab checkout, invoke `python3 lab.py` with the same arguments.
The case compares actual node placement and taint handling. The ordinary
nonroot fractional workload observes its exact CPU quota and 32 MiB
memory limit in cgroup v2. An eligible Guaranteed workload receives one
exclusive CPU on the same AI node, and that CPU leaves the shared CPU set.

## Verify the adopted node classes and workloads

1. Inventory Kubernetes, kernel, runtime and node images, CPU and memory
   controllers, designated node pools, and the workload classes they
   host. Verify actual labels, taints and authorized selectors.
2. Observe `cpu.max`, `memory.max` and `cpuset.cpus.effective` in a
   representative workload for each node class. Compare the values
   with the workload requirements and Pod specification. Preserve
   sanitized records linking the Pod, container and node.
3. For workloads that require exclusive CPUs, verify kubelet CPU
   Manager static policy, processor reservations, Guaranteed QoS and
   the applicable integer CPU requests. Compare the effective
   exclusive and shared CPU sets before and after placement. Repeat
   after a planned node image or runtime change.
4. For required NUMA alignment, verify the actual topology and
   documented CPU, memory and device hint providers. Capture the
   effective kubelet policies and reservations and verify allocation
   from a representative workload on the actual hardware.
5. Where isolation objectives include performance or interconnect
   behavior, run a bounded approved comparison with the declared
   colocated workload and measured acceptance thresholds. Keep these
   measurements alongside resource and placement evidence.

[Kubernetes CPU Manager](https://v1-36.docs.kubernetes.io/docs/tasks/administer-cluster/cpu-management-policies/),
[Kubernetes Memory Manager](https://v1-36.docs.kubernetes.io/docs/tasks/administer-cluster/memory-manager/),
and [Kubernetes Topology Manager](https://v1-36.docs.kubernetes.io/docs/tasks/administer-cluster/topology-manager/).
