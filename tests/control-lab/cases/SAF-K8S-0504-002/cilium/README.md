# SAF-K8S-0504-002 Cilium runtime

From the SAF-K8S framework root, run using local Docker, Kind 0.32.0, Helm,
kubectl and a Linux Kind kernel with WireGuard and nftables netdev support.

```sh
python3 tests/control-lab/cases/SAF-K8S-0504-002/cilium/run.py --docker-context desktop-linux
```

In the source lab, use the same command starting at `cases/`. The runner
checks the OCI chart digest and starts Cilium 1.20.5 with native routing and
bundled SPIRE on a disposable three-node Kind cluster. The same inert client
and server pairs exercise the SPIRE identity policy before and after it
is applied.

The test also proves the live cross-node WireGuard path on this setup.
Passive counters on each receiving WireGuard interface start at zero.
An inert HTTP request and response match the exact Pod IPs and TCP ports,
and both counters advance for the cross-node connection. Both counters stay
at zero for the successful same-node comparison. The case also checks
reciprocal peer keys and recent handshake state. Deployed traffic paths
and any separate same-node protection require deployment evidence.

[Cilium 1.20.5 WireGuard guide](https://docs.cilium.io/en/stable/security/network/encryption-wireguard/), [nftables network device hooks](https://netfilter.org/projects/nftables/manpage.html)
