# SAF-K8S-0702-013 — Tenant ingress and egress isolation

```sh
python3 lab.py test SAF-K8S-0702-013 --docker-context desktop-linux
```

The case provisions two kind nodes and uses kind v0.32's stock kindnet
NetworkPolicy implementation. It places the fixture clients on the control
plane node and the HTTP services on the worker. Every request uses a fixed
port and one case-owned Pod IP. The successful response must carry the
expected public marker.

Before policy, all case paths work across the nodes. The source's
default-deny policy blocks only its egress path while the unisolated peer
still reaches the same endpoint. Adding the exact egress allow restores the
path. The destination tenant's default-deny policy then blocks ingress,
and adding its exact ingress allow restores the approved path again. An
unapproved client, peer namespace, and destination remain denied. Each
step requires two consecutive observations to account for policy convergence.

The test covers ordinary IPv4 TCP Pod traffic and deletes both nodes.
Production review still covers deployed plugins, address families, tenant
enrollment, DNS, node and host-network exceptions, and the documented
allowlist and review process.

- [Kubernetes v1.36 NetworkPolicy semantics](https://v1-36.docs.kubernetes.io/docs/concepts/services-networking/network-policies/)
- [kind's built-in NetworkPolicy implementation](https://github.com/kubernetes-sigs/kind/releases/tag/v0.24.0)
