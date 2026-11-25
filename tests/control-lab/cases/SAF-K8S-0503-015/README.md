# SAF-K8S-0503-015 — Approved DNS resolution path enforcement

```sh
python3 lab.py test SAF-K8S-0503-015 --docker-context desktop-linux
```

The Kubernetes v1.36.1 Kind fixture uses the bundled kindnet CNI, two local
DNS responders, and two clients in one owned namespace. Each resolver
returns a different documentation-only address for the same reserved test
name. The fixture verifies that both clients can query both responders on
UDP and TCP ports 5353 and 5354 before enforcement.

A native egress NetworkPolicy matches exactly the selected client and
permits only UDP and TCP port 5353 to the approved responder Pod. The
selected client keeps that approved path. An unapproved resolver and the
approved responder's alternate port stop returning DNS answers to it. The
unselected comparison workload still gets corresponding answers, including
from the alternate port.

This verifies address and port enforcement for one enrolled workload with
one applicable NetworkPolicy. Kubernetes egress policies are additive
across applicable rules. Deployment evidence covers effective CNI policy
composition, actual CoreDNS or resolver routing, node-local DNS, and any
external proxy or DNS-aware enforcement in use.

- [Kubernetes v1.36 Network Policies](https://v1-36.docs.kubernetes.io/docs/concepts/services-networking/network-policies/)
- [Kubernetes v1.36 DNS for Services and Pods](https://v1-36.docs.kubernetes.io/docs/concepts/services-networking/dns-pod-service/)

## Verify an adopting implementation

Inventory effective egress policy unions for representative workloads, including namespace and Pod selectors, hostNetwork exceptions, NodeLocal DNSCache, and the deployed CNI/provider enforcement path. Document approved CoreDNS or DNS-proxy endpoints, UDP and TCP ports, upstream forwarding configuration, and any node-local or external resolver routes. Use authorized deployment fixtures to confirm approved resolution succeeds and alternate resolver paths fail over UDP and TCP for selected workloads, while an unselected comparator remains unaffected. Retain policy/API snapshots, resolver configuration, flow or DNS observations, exception approvals, and policy drift ownership.
