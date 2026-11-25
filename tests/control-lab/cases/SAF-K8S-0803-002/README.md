# SAF-K8S-0803-002 Ordinary IP segmentation example

Two harmless peers initially reach an owned HTTP listener. An actual Kubernetes ingress policy restricts the selected TCP port to the approved peer while the same listener remains healthy. This is an IP-network observation on the installed Kind CNI. It does not demonstrate Ethernet ACL, InfiniBand partition, RoCE device, or hardware fabric enforcement.

## Adopter verification

1. Inventory actual interconnects, hardware and protocol, adapters, tenant segmentation, access controls and the authority for configuring the physical or virtual fabric.
2. Verify intended protocol-specific separation, destination and route decisions and actual adapter assignment using approved inert workload traffic. Confirm an authorized path remains available and an unapproved path is blocked at the expected boundary.
3. Retain provider or administrator configuration, observed membership, protocol and decisions, access records and exceptions. Repeat when fabric, tenant or topology changes.
