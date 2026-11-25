# SAF-K8S-0503-016 — Namespace-scoped DNS service discovery restriction

```sh
python3 lab.py test SAF-K8S-0503-016 --docker-context desktop-linux
```

Kubernetes v1.36 resolves namespace-qualified Service names across namespaces. `NetworkPolicy` supplies peer, address, protocol, and port restrictions. Name-level discovery requires a DNS-aware enforcement mechanism, such as the exact DNS-name rule tested here. [Kubernetes Service DNS](https://v1-36.docs.kubernetes.io/docs/concepts/services-networking/dns-pod-service/), [Kubernetes NetworkPolicy](https://v1-36.docs.kubernetes.io/docs/concepts/services-networking/network-policies/), [Cilium DNS policy at v1.20.5](https://github.com/cilium/cilium/blob/v1.20.5/Documentation/security/policy/layer7.rst).

On a fresh Kubernetes v1.36.1 Kind cluster, the case installs Cilium 1.20.5 from a SHA-256-checked Helm chart. Cilium installs its exclusive CNI configuration before the fixture Pods are created. CoreDNS is rolled out again so its Pods also get Cilium identities, and the case confirms the identities for CoreDNS and both clients before issuing queries.

1. Two client Pods query the same two synthetic, fully qualified cross-namespace Service A records over UDP. Both clients must see the correct answers before the policy is installed.
2. A namespaced CiliumNetworkPolicy enrolls only the selected client. It authorizes the exact approved name through CoreDNS. The selected Pod must receive the correct approved answer and DNS `REFUSED` for the unapproved name, each twice consecutively.
3. The unselected comparison Pod must retain both correct answers for the same queries. Each check matches the DNS transaction and requires the specific result.

All 11 assertions passed in `evidence/SAF-K8S-0503-016/20261122T091044Z-1a3c141b/result.json` on Kubernetes v1.36.1. The test covers the two owned A records in one CNI and resolver configuration. Effective policy across deployed namespaces and workloads, other record types and resolver paths, and cross-tenant inventory coverage require separate evidence. The tested control concerns DNS discovery. Service connectivity and authorization require their own controls.

## Verify an adopting implementation

Inventory CoreDNS or managed DNS topology, NodeLocal/proxy components, CNI DNS-aware policy version, tenant namespaces and the source identities those policies select. For representative tenant canaries, verify approved and out-of-scope A/AAAA/SRV or other required record lookups against the deployed resolver; record DNS decision separately from service connection authorization. Check policy rollout, exceptions and ownership across all clusters and workload classes; verify DNS results cannot be mistaken for authorization to connect to the returned address. Retain resolver, policy and workload inventory snapshots plus sanitized positive/negative query evidence and drift alerts.
