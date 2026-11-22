# SAF-K8S-0504-002 Cilium runtime

From the SAF-K8S framework root, run using local Docker, Kind 0.32.0, Helm,
kubectl and a Linux Kind kernel with WireGuard support.

```sh
python3 tests/control-lab/cases/SAF-K8S-0504-002/cilium/run.py --docker-context desktop-linux
```

In the source lab, use the same command starting at `cases/`. The runner
checks the OCI chart digest and starts Cilium 1.20.5 and bundled SPIRE in a
disposable three-node cluster. An owned client sends the same inert request
to one server on its node and another on the second worker, before and after
applying fixture authentication policies. The Cilium logs must report the
exact fixture identity pairs after applying the policies.

The case checks reciprocal node public keys, applicable WireGuard peers,
recent handshakes and bidirectional peer traffic for the cross-node path.
Peer counters are shared by the nodes. Assess same-node transport encryption,
individual workload flow coverage and production protection separately.

[Cilium 1.20.5 WireGuard guide](https://docs.cilium.io/en/stable/security/network/encryption-wireguard/)
