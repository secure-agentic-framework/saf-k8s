# SAF-K8S-0205-008 Service proxy mode selection

Two disposable Linux Kind nodes run Kubernetes v1.36.1 with nftables kube-proxy.
An authorized fixture reviewer stores the versioned mode decision. The read-only
operator can inspect it and cannot write it. The case distinguishes an older
iptables decision from the selected nftables configuration, observes mode in
both proxy processes, and confirms the owned TCP ClusterIP tuple in both kernels.
The same client verifies endpoint selection and replacement on the other node,
then rechecks the effective proxy mode and marker after recreating the proxy Pods.

```sh
python3 lab.py test SAF-K8S-0205-008 --docker-context desktop-linux
```

## Verify an adopter profile

1. Inventory Kubernetes, node OS/kernel, CNI, running Service implementation,
   address families, required Service types, protocol behavior and owned
   provider boundaries. Confirm supported modes for that exact release and
   platform. Record the chosen backend and alternatives, approver, owners,
   prerequisites, decision scope, exceptions and recheck triggers.
2. Compare the approved record with the applied kube-proxy config and live
   process state, or the supported provider/CNI replacement and its effective
   state. Observe the Service tuple in the effective rules or approved
   datapath output. Keep logs, relevant rules, Service and EndpointSlice
   state, and provider attestation with their version and collection times.
3. In a matching disposable profile, verify an absent endpoint, a known
   selected endpoint, replacement, and recovery after proxy or node lifecycle
   events. Use only owned marker paths. Include every required Service type
   and IP family, applicable source/traffic policies and health checks.
4. Keep mode governance independent of throughput, convergence SLOs and
   hardening claims. Measure with representative traffic as needed. Reopen the
   decision after platform, proxy, provider or required Service path changes.

Additional modes and profile-specific traffic are assessed against their own
approved baseline. This fixture covers Linux IPv4 TCP ClusterIP with nftables.

- [Kubernetes v1.36 virtual IP and Service proxy modes](https://v1-36.docs.kubernetes.io/docs/reference/networking/virtual-ips/)
- [Kubernetes v1.36 RBAC authorization](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/)
