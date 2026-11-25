# SAF-K8S-0103-005 — Pod garbage collection threshold

Run this case on disposable kind clusters with the pinned Kubernetes v1.36.1
image. The runner provisions a default cluster. The case provisions a second
cluster with `--terminated-pod-gc-threshold=2` and checks the controller
process arguments through its mirror Pod.

Both profiles run the same three bare BusyBox Pods with automatic service-account
token mounting disabled. The Pods exit with codes 0, 17, and 0 respectively.
The case observes each exact terminal phase before checking retention. It places
the oldest Pod in one namespace and the two newer Pods in another. Neither
namespace has more than two terminal fixtures, so the configured profile must
use the count across namespaces to remove the oldest Pod. The default profile
retains all three across the same observation window. A separate running Pod
remains Ready in both clusters.

Use this result to verify count-based collection. Deletion after a fixed maximum
age requires a separate lifecycle policy. Deployment-specific retention needs and
managed providers' effective settings are tracked in Beads.

- [Kubernetes v1.36 controller-manager reference](https://v1-36.docs.kubernetes.io/docs/reference/command-line-tools-reference/kube-controller-manager/)
- [Kubernetes v1.36 Pod lifecycle](https://v1-36.docs.kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle/#garbage-collection-of-pods)
- [PodGC implementation at v1.36.1](https://github.com/kubernetes/kubernetes/blob/v1.36.1/pkg/controller/podgc/gc_controller.go)

## Adopter verification

Record the effective controller-manager terminated Pod threshold, cluster
version, owner and approved job diagnostics retention. Inventory terminated
Pod counts across namespaces and confirm the selected positive threshold is
appropriate to the observed batch workload. In an approved representative
fixture, compare excess terminated Pod removal, retained current records
and continued execution of nonterminated workloads. Retain the measured
cluster state and configuration source. Document the separate lifecycle
policy if the workload needs an upper age limit. For managed settings,
collect version-specific evidence from the responsible provider and record
which part of retention is customer-configurable.
