# SAF-K8S-0203-008 — Workload egress path enforcement

```sh
python3 lab.py test SAF-K8S-0203-008 --docker-context desktop-linux
```

The disposable dual-stack Kind cluster hosts two TCP marker listeners on
its ordinary Pod addresses. Both respond before policy. The CNI egress
policy selects one ordinary workload, which loses the unapproved marker
on both IPv4 and IPv6 while retaining the approved path. An unselected
diagnostic Pod and both server logs establish that the listeners stayed
healthy. Removing the policy restores the paths. A separate API dry-run
shows that Restricted Pod Security refuses a host-network declaration
in this namespace.

## Verify deployment applicability and evidence

1. Inventory the approved provider identity path, governed caller classes,
   effective IPv4/IPv6 and DNS or proxy routes, provider exceptions, CNI
   mode and network-policy implementation for each eligible node pool.
2. Use read-only provider and Kubernetes configuration to identify the
   real enforcement point. Map egress rules to the expected packet path
   and identify traffic with separate host, node, provider or proxy control.
   Preserve required identity access and dependencies.
3. In isolated staging, use owned marker listeners and authorized test
   identities. Verify the denied and approved responses for each affected
   caller class and address family. Check the appropriate server evidence,
   convergence and a reachable control path to distinguish enforcement from
   a listener, DNS, or route failure. Validate DNS-mediated paths separately
   when used.
4. Validate host-network admission, host and node routing or firewall state,
   and provider settings on their respective surfaces. For managed pools,
   collect scoped provider evidence where direct read-only observation is
   unavailable. Record the applicable version, inventory, ownership,
   separately governed exceptions and retained dependencies.

The fixture exercises direct Pod addresses and declaration admission.
Provider metadata services, real credential paths and host traffic require
their own evidence.

[Kubernetes v1.36 NetworkPolicy](https://v1-36.docs.kubernetes.io/docs/concepts/services-networking/network-policies/) ·
[Kind dual-stack configuration](https://kind.sigs.k8s.io/docs/user/configuration/) ·
[EKS identity boundaries](https://docs.aws.amazon.com/eks/latest/best-practices/identity-and-access-management.html) ·
[GKE workload identity](https://docs.cloud.google.com/kubernetes-engine/docs/concepts/workload-identity) ·
[AKS IMDS restriction](https://learn.microsoft.com/en-us/azure/aks/imds-restriction)
