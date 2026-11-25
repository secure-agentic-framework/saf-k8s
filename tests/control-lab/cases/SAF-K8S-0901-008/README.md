# SAF-K8S-0901-008 training workload network isolation

Run from the framework checkout:

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0901-008 --docker-context desktop-linux
```

The two-node fixture uses the pinned Kubernetes v1.36.1 image and the native
kindnet implementation. Synthetic source and peer Pods communicate over
IPv4 TCP. The first comparison observes baseline reachability to the
authorized peer and the wrong-namespace and wrong-label comparators. The
exact egress policy restores the approved path and limits the selected source
while an unrelated positive path still works.

A separate marker source is pinned to the case control-plane node. The
approved marker target and existing wrong-label peer run on the worker node.
The test directly verifies their placements and reaches both targets at
baseline. With the same exact policy applied, the approved worker marker
continues to respond and the cross-node wrong-label peer is denied. The
runtime does not include an accelerator or a production training framework.

## Verify an adopting implementation

1. Inventory each governed namespace, workload selector, node topology, CNI,
   address family, training port, and accelerator fabric. Identify the
   owners authorized to change workload and namespace labels and policy.
2. Validate the effective CNI rules and their combined behavior. From
   representative training workloads, compare the approved peer path and
   excluded peers on different nodes. Cover IPv6, DNS, routing, host-network
   interfaces and service paths where applicable.
3. Verify RDMA, InfiniBand, NCCL and other fabric isolation separately when
   deployed. Identify paths outside the CNI and preserve provider or fabric
   coverage, permitted and denied observations, exceptions and change logs.
4. Reconcile these results against training templates and define drift and
   exception review. Keep proof tied to the applicable implementation version.

[Kubernetes v1.36 NetworkPolicy](https://v1-36.docs.kubernetes.io/docs/concepts/services-networking/network-policies/)
and [NIST SP 800-53 Rev. 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final).
