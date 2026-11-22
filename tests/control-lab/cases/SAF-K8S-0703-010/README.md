# SAF-K8S-0703-010 — Node isolation and CPU Manager static behavior

```sh
python3 lab.py test SAF-K8S-0703-010 --docker-context desktop-linux
```

The three-node kind setup enables CPU Manager static. The scheduler
places a fractional test Pod on the AI worker and an ordinary Pod
on the general worker. A Pod requesting the AI pool without its
required toleration remains unscheduled for the observed taint.

The fractional nonroot Pod reports multiple CPUs in its effective
shared set. It reads the declared one-tenth CPU quota and 32 MiB
memory limit from cgroup v2. A Guaranteed integer-CPU Pod placed
on the same worker receives exactly one CPU, and the live shared
pool no longer contains that CPU. The two test processes are inert.

Kernel CPU and memory settings are separate from scheduling placement.
NUMA memory allocation, topology and interconnect settings, interference
under production loads, configuration persistence and real accelerator
nodes require their own evidence.

- [Kubernetes v1.36 CPU Manager](https://v1-36.docs.kubernetes.io/docs/tasks/administer-cluster/cpu-management-policies/)
- [Kubernetes v1.36 container resource management](https://v1-36.docs.kubernetes.io/docs/concepts/configuration/manage-resources-containers/)
- [Kubernetes v1.36 taints and tolerations](https://v1-36.docs.kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration/)
