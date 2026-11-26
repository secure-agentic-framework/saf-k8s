# SAF-K8S-0501-003 — Workload egress to approved destinations

```sh
python3 lab.py test SAF-K8S-0501-003 --docker-context desktop-linux
```

A benign client first reaches three live address and port combinations on
two owned Docker peers outside the Kubernetes cluster. A workload-scoped
NetworkPolicy allows one peer IPv4 /32 and TCP/8080. The same client still
retrieves the approved marker, while the other IP and the alternate port
on the approved IP are blocked. Both denied listeners independently return
their markers locally. The fixture removes the peers and bridge afterward.

A second phase repeats the default-deny and permitted-route observations
for two owned in-cluster listeners. The selected namespace and Pod labels
restore only the approved TCP route.

The fixture covers kindnet IPv4 and direct connections on the test-owned
networks. Verify FQDN filtering on the intended CNI, provider routing and
egress gateways, DNS controls, and deployed external-service inventory
separately.

[Kubernetes NetworkPolicy](https://v1-36.docs.kubernetes.io/docs/concepts/services-networking/network-policies/)

## Verify workload egress in the adopted environment

1. Record each workload identity and namespace, required service, protocol and
   port, approved addresses or DNS names, configured resolver and enforcement
   point. Identify path translation or intermediaries such as an egress gateway.
   Retain the reviewed rule and service owner for each allowance.
2. In a disposable matching environment, compare an approved exact marker,
   a healthy listener on another address, and a healthy listener on an
   unauthorized port at the approved address. Confirm the approved path
   remains reachable after enforcement and capture the independent listener
   health and exact denied decisions. Repeat for each used address family
   and authorized alternate route.
3. If names govern access, test a version and edition with DNS-aware egress.
   Confirm the approved name resolves through the permitted resolver and
   reaches its marker. An alternate name may still resolve but must not
   reach its listener. Repeat after address or TTL changes and verify the
   configured path for ungoverned resolvers, direct addresses and address
   reuse. [SAF-K8S-0501-004 demonstrates the Cilium exact-name comparison](https://github.com/secure-agentic-framework/saf-k8s/blob/0e06d9f06eb306a1052bfc270c38c31085fb2c53/tests/control-lab/cases/SAF-K8S-0501-004/README.md).
4. Where used, verify provider routing, enforced gateway rules and provider
   metadata restrictions through the same governed workload and an owned
   test environment. Use a configuration review or safe mock metadata
   endpoint for this portable test. Confirm denied requests produce no
   effect at the owned receiver. Retain the effective policy, resolver and
   routes with the allowed and denied observations.

The direct route fixture uses IPv4 kindnet. The companion uses pinned Cilium.
Check the installed CNI edition and capabilities before selecting the
corresponding cloud or Calico DNS-aware procedure.
