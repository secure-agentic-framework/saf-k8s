# SAF-K8S-0803-006 Policy administration boundary

Two synthetic operators manage owned Kubernetes records representing host and offload policies. The test demonstrates an overly broad shared role, removes it, and verifies actual namespaced access and preserved read-only visibility. It uses no DPU, SmartNIC, BMC, or network management interface.
