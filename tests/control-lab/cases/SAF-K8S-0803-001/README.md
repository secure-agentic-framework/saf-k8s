# SAF-K8S-0803-001 Placement policy around accelerator domains

The test uses two disposable Kind nodes and CPU-only Pods. It observes a denied contrary domain and verifies successful scheduling to two separate selected nodes. Those nodes and labels model an approved assignment boundary. They do not expose or isolate an NVLink, NVSwitch, GPU topology, or physical fabric.

## Adopter verification

1. Map each workload class to physical accelerator topology, fault and trust domains, host adapters, switch ports and the Kubernetes node pool that represents those boundaries.
2. Verify authoritative topology and label ownership independently. Run authorized canaries to check scheduler placement, actual device and fabric assignment, and absence of unintended cross-boundary reachability.
3. Retain topology, exact device and adapter identifiers, versions, approved flows, placement evidence, exceptions and review dates. Recheck after topology or pool changes.
