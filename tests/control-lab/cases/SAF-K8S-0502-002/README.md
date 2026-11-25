# SAF-K8S-0502-002 — Cross-node pod encryption

Run from the framework repository.

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0502-002 --docker-context desktop-linux
```

The two-node kind cluster uses Kubernetes v1.36.1 and the digest-pinned Cilium 1.20.5 chart in IPv4 native routing mode. It requires Helm and kernel WireGuard support. The case checks the selected Pods are placed on different nodes, then requests an exact synthetic response on the unencrypted baseline. After enabling Cilium WireGuard, it verifies both expected remote Pod addresses are covered by the reciprocal peer configurations and saves the reviewed address sets in `wireguard-peers.json`. It measures the interface counters around the same response in both directions. The byte counts are retained separately in `wireguard-counters.json` because background CNI work can also contribute to the interface totals.

This verifies the covered cross-node Cilium path. Other CNI modes, same-node traffic, services, host networking and deployed performance need separate evidence. [Cilium 1.20.5 WireGuard coverage](https://docs.cilium.io/en/stable/security/network/encryption-wireguard/)

## Adopter verification

Inventory the deployed CNI, version, encryption mode and every applicable Pod path, including cross-node, same-node, Service, host-network and any provider-managed routes. Verify actual peer coverage and key/handshake state using vendor-supported evidence. Run an approved representative workload to measure throughput/latency and compare with the documented performance budget. Record threat-model exceptions and remediation/rotation ownership.
