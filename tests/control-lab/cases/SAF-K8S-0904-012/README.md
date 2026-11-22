# SAF-K8S-0904-012 — Explicit cross-classification approval

The source submits a fixed marker event to an in-cluster gateway. Receivers
for public and restricted stages are distinct Pods. Their ingress policy
accepts traffic from the gateway. The test checks the public receiver's
actual bytes and typed decision receipts before and after enabling the gate.
Missing and mismatched approvals leave the public receipt absent. The exact
immutable approval allows the transfer, and the separate ordinary route
remains available.

The fixtures exercise a controlled gateway and native Kubernetes transport.
Production approval custody, identity and policy integration, persistent
stores, and downstream derived data need separate evidence.
