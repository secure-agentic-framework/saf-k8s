# SAF-K8S-0803-006 Policy administration boundary

Two synthetic operators manage owned Kubernetes records representing host and offload policies. The test demonstrates an overly broad shared role, removes it, and verifies actual namespaced access and preserved read-only visibility. The positive phase now also submits an actual cross-scope patch from the offload operator to the host record, requires a Kubernetes `forbidden` authorization response, and independently reads the host record to confirm its approved revision remained unchanged. The case still has three checks. It uses no DPU, SmartNIC, BMC, or network management interface.

The portable cross-scope check gives the modeled offload operator read-only
visibility to the named host ConfigMap so kubectl can issue the PATCH after its
initial GET. The API denies the PATCH and the independently read host revision
stays at the approved value.
