# SAF-K8S-0201-007 hard kubelet eviction threshold

Run `python3 tests/control-lab/lab.py test SAF-K8S-0201-007 --docker-context desktop-linux`
from the framework root.

The test raises the worker hard memory threshold above observed free memory while leaving positive
allocatable capacity while a small, bounded Pod is healthy. It observes the native
pressure signal and termination of that Pod before its configured grace
period. The PodDisruptionBudget permits zero voluntary disruptions before
pressure. The control plane stays ready. The original worker settings are
restored and a new ordinary Pod becomes ready.

The raised value creates a controlled condition without consuming excess
memory. Production values, physical capacity protection, storage
thresholds, managed service and GPU-specific tuning remain separate.

- [Kubernetes v1.36 node-pressure eviction](https://v1-36.docs.kubernetes.io/docs/concepts/scheduling-eviction/node-pressure-eviction/)

## Verify your implementation

- Inventory node pools, reservations, allocatable capacity, filesystem topology,
  supported eviction signals, and any managed settings. Record the running kubelet
  release, the complete effective hard threshold map, the merge setting, and
  evidence that the provisioning source reproduces those settings after restart
  or node replacement.
- Compare thresholds and system and Kubernetes reservations to observed memory,
  filesystem space, inodes, and PID headroom as applicable. Look at sustained and
  burst load, telemetry sampling cadence, and the capacity the node needs to
  recover. Hard memory thresholds reduce risk. Rapid increases can still outrun
  the kubelet and the kernel can invoke its OOM killer.
- Distinguish explicit overrides, disabled thresholds, and versioned defaults.
  The test compares one effective inode threshold with the merge setting off and
  on, then confirms restoration before the memory scenario. Filesystem topology,
  the runtime and feature support determine which signals apply.
- Rehearse expected pressure signals, alert delivery, and workload recovery in
  approved staging. Verify rescheduling and any checkpoint or retry policy with
  workload owners. A hard eviction can interrupt a workload before its configured
  grace period, including one with a PDB. Preserve the thresholds and reasons in
  the rehearsal evidence and each deviation's approval and expiry.
- For a managed pool, retain service and node-pool evidence of effective policy
  and operator responsibilities. For GPU workloads, assess device-memory capacity
  and recovery with the GPU mechanisms. Kubelet node-memory measurements describe
  host memory.

- [Kubernetes v1.36 kubelet configuration](https://v1-36.docs.kubernetes.io/docs/reference/config-api/kubelet-config.v1beta1/)
- [Kubernetes v1.36 resource reservations](https://v1-36.docs.kubernetes.io/docs/tasks/administer-cluster/reserve-compute-resources/)

## Native storage and PID evidence

On this sample Linux node layout, the case isolates `nodefs.available`,
`nodefs.inodesFree`, and `pid.available` one at a time. It reads the actual
worker's reported headroom and temporarily raises the selected threshold.
The case observes the expected Node condition and kubelet admission denial
for a directly bound Pod. It checks the exact pressure message and verifies a
fresh healthy Pod after restoration. The earlier memory comparison observes
termination of a running Pod. The runner never creates disk, inode, or process exhaustion.

Kind's runtime can report the same backing filesystem for multiple identifiers.
Use the runtime's supported layout and observed kubelet statistics to identify
effective `nodefs`, `imagefs`, and `containerfs` coverage. If the platform uses
a separate image or container filesystem, verify the corresponding reclamation,
eviction and recovery in representative staging. Record unsupported or aliased
signals and report actual per-pool capacity, alert delivery, and recovery
evidence as part of the adopter's assessment.
