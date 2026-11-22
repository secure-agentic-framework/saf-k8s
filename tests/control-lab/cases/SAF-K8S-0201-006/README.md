# SAF-K8S-0201-006 — Node system and kube reserved resource allocations

```sh
python3 lab.py test SAF-K8S-0201-006 --docker-context desktop-linux
```

Two case-owned kind Kubernetes v1.36.1 clusters use the same digest-pinned
image and stock eviction settings. The baseline uses the ordinary kubelet
reservation settings. The second adds `systemReserved` and `kubeReserved`.
The test compares each Node's capacity-to-allocatable gap across the pair.
The expected added reservation is 60 millicores, 80 MiB of memory, and 3 MiB
of ephemeral storage. The storage fixture includes both reservation settings.
The runner verifies both clusters are cleaned up.

The result measures advertised Node Allocatable. Daemon cgroup setup remains
a separate enforcement obligation. Production reserve sizing, provider
availability, workload-pressure response and GPU workloads require separate
evidence. The framework retains `verified/SAF-K8S-0201-006.json`.

- [Kubernetes v1.36 Node Allocatable and daemon reservations](https://v1-36.docs.kubernetes.io/docs/tasks/administer-cluster/reserve-compute-resources/)
- [Kubelet v1.36.1 reservation implementation](https://github.com/kubernetes/kubernetes/blob/v1.36.1/pkg/kubelet/cm/node_container_manager_linux.go)
