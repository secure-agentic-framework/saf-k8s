# SAF-K8S-0501-006 — Cross-cluster transport identity and network isolation

```sh
python3 lab.py test SAF-K8S-0501-006 --docker-context desktop-linux
```

The case creates two disposable Kind clusters with an internal bridge between
their owned nodes. A synthetic client in the source cluster submits a harmless
`GET /health` to the peer cluster. Each API command selects its own context
and temporary kubeconfig.

The same peer route first accepts a request without client authentication. The
client rejects a mismatched server hostname. After mutual TLS is enabled, a
missing certificate fails at TLS, a trusted wrong URI SAN receives 403, and the
approved certificate stays usable.

The source client can initially reach two ports on the peer cluster.
NetworkPolicy preserves the approved peer IP and TCP port. It denies the
alternate port while an independent client retains access to it. The fixture
correlates bounded client and peer events for the permitted flow and checks
that the denied flow never reaches the peer HTTP handler. Both clusters and
the bridge are removed.

Deployed mesh, trust rotation, provider networking, and operational flow
collection require separate evidence.

[Kubernetes v1.36 NetworkPolicy](https://v1-36.docs.kubernetes.io/docs/concepts/services-networking/network-policies/) ·
[Kubernetes Multi-Cluster Services API](https://github.com/kubernetes/enhancements/tree/master/keps/sig-multicluster/1645-multi-cluster-services-api) ·
[Python TLS verification](https://docs.python.org/3/library/ssl.html#security-considerations)

## Verify the adopted cross-cluster paths

1. **Inventory effective paths.** For each cluster pair, document workload
   identities, destination services, ports, protocols, IP families, DNS,
   routes, interconnects, NAT, gateways, NodePort/LoadBalancer/MCS paths, and
   any host-network or alternate path. Identify who approves each path and
   ensure its actual CNI/network implementation enforces the intended policy.
2. **Verify the route policy.** In an approved non-production environment,
   use owned harmless endpoints. Confirm one exact approved route succeeds,
   a neighboring port/address route is denied, and an independent health
   client proves the denied listener remains healthy. Inspect the effective
   policy and CNI decision for the same workload and route. Check alternate
   gateways, nodes, IPv6, and failover paths as applicable.
3. **Verify transport identity.** Confirm the client validates the server
   chain and expected DNS name/SAN. Require client certificates on every
   relevant cross-cluster route. Verify that a missing certificate fails
   before HTTP, an untrusted certificate is refused, a trusted but
   unauthorized workload identity cannot access the service, and the exact
   authorized identity succeeds. Repeat against each server endpoint and
   ingress path, including failover destinations.
4. **Exercise trust rotation.** This reference does not rotate trust. For
   deployment acceptance, rehearse a separately approved overlap: distribute
   a bundle containing old and new trust anchors, verify old and new server
   leaves while each client trust store is updated, rotate client identities,
   confirm every peer is on the new trust, then remove the old anchor. Retain
   versioned bundle/leaf identifiers, workload identity, handshake result,
   rollout status, and rollback readiness. Do not record keys or certificate
   contents. Verify revocation or emergency replacement paths separately.
5. **Verify independent flow observations.** Correlate a stable flow/request
   identifier across source workload telemetry and destination service or
   network telemetry. The allowed route should appear on both sides; a
   network-denied route should not appear at the destination, while a separate
   health route confirms that observation remains live. Confirm the same
   events reach the operational collection/alert path, preserve timestamps
   and cluster/workload identities, and document retention and access. Do not
   treat test-generated app receipts as proof that a production collector is
   configured.
6. **Capture the boundary.** Record the CNI, mesh/gateway and versions,
   trust-bundle revision, policy revision, tested source/destination
   identities, allowed/denied outcomes, independent observation sources,
   rotation evidence, responsible owners, and remaining untested routes.
   Keep production claims limited to the covered cluster pairs and paths.

## Standards and implementation references

- [NIST SP 800-53 Rev. 5, Update 1](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)
- [Kubernetes v1.36 NetworkPolicy](https://v1-36.docs.kubernetes.io/docs/concepts/services-networking/network-policies/)
- [Python 3.13 TLS security considerations](https://docs.python.org/3.13/library/ssl.html#security-considerations)
- [Kubernetes Multi-Cluster Services API KEP-1645](https://github.com/kubernetes/enhancements/tree/master/keps/sig-multicluster/1645-multi-cluster-services-api)
