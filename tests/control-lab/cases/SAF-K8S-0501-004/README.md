# SAF-K8S-0501-004 — Cilium policy enforcement

```sh
python3 lab.py test SAF-K8S-0501-004 --docker-context desktop-linux
```

The fixture starts a pinned kind cluster, verifies the SHA-256 of the
published Cilium 1.20.5 Helm archive, and installs it only in the
runner-owned context. Cilium takes ownership of CNI configuration before
the case creates its two HTTP Pods. Helm must be available locally.

The original HTTP-method check remains: before policy, GET and POST to the
same test listener and path return the exact harmless marker; afterward GET
still returns it and Cilium denies POST with HTTP 403.

Additional checks create two owned HTTP fixtures on a disposable Docker
`--internal` bridge attached only to the kind node. The case verifies distinct
fixture IPv4 addresses, starts an owned DNS responder with exact A records for
two `.test` names, and directs the test client's resolver only to that Pod.
Before policy both names resolve to their recorded addresses and return their
individual markers. After policy, selective DNS proxy rules keep both names
resolvable, while `toFQDNs.matchName` authorizes HTTP only to the approved
exact name. The alternate HTTP request must fail, and both fixture listeners
must still return their markers when checked locally inside their containers.

Three additional owned namespaces each have a probe Pod. Namespaced Cilium
allows first establish real access to the owned HTTP fixture from two
selected namespaces. A CiliumClusterwideNetworkPolicy then selects only those
two namespaces and denies the same destination and port. Both selected probes
must lose access despite the namespaced allows; the third namespace must
retain access.

All HTTP, DNS, IPs, peers, namespaces and policy resources are case-owned and
local to this run. This does not establish public DNS behavior, production
FQDN policy safety, Calico behavior, cloud-provider behavior, or behavior on
other Cilium versions.

[Cilium 1.20 Layer 3 / `toFQDNs`](https://docs.cilium.io/en/v1.20/security/policy/layer3/) ·
[Cilium 1.20 DNS proxy / Layer 7](https://docs.cilium.io/en/v1.20/security/policy/layer7/) ·
[Cilium 1.20 namespace selectors](https://docs.cilium.io/en/v1.20/security/policy/kubernetes/) ·
[Cilium 1.20 deny precedence](https://docs.cilium.io/en/v1.20/security/policy/deny/) ·
[Cilium v1.20.5 release](https://github.com/cilium/cilium/releases/tag/v1.20.5) ·
[Cilium CNI configuration](https://docs.cilium.io/en/v1.20/network/kubernetes/configuration/)

## Kubernetes NetworkPolicy comparison

With the pinned Cilium data plane running, the case applies a standard `networking.k8s.io/v1` ingress policy to the owned listener. Its selected client retains GET and POST on the approved TCP port. The unselected client reaches the listener before the policy, loses access after enforcement, and recovers after removal. The independent Cilium HTTP-method, DNS-name and cluster-wide policy checks then run on their own fixture paths.

Verify the actual CNI and policy versions, label and namespace selectors, IP families, rule precedence, and coverage of each adopted ingress and egress path. Rehearse both authorized and denied cases on approved test workloads. Record provider limitations and equivalent compensating controls with their own tests and accountable owners.

## Adopter verification

Record the approved CNI version and effective configuration. Inventory standard and plugin-specific network policies, namespace and workload selectors, approved port and method rules, intended names and DNS paths, and cluster-wide policy precedence. Exercise each governed route and a neighboring unselected route against the same representative test service. Include alternate addresses, host or node traffic, private resolver behavior and exception paths where applicable. Retain the actual policy, source and destination identities, result, date and accountable approval.

The revised catalog retains bounded supporting mappings for AC-4, AC-4(21), CA-9, SC-7, SC-7(5), and SC-7(11). Each applies at the tested information-flow, interface, or component boundary under its conditions. Record unverified paths and compensating measures in the adopter assessment.

[Kubernetes v1.36 NetworkPolicy](https://v1-36.docs.kubernetes.io/docs/concepts/services-networking/network-policies/) · [Cilium v1.20 policy language](https://docs.cilium.io/en/v1.20/security/policy/language/)
