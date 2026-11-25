# SAF-K8S-0702-013 — Tenant ingress and egress isolation

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0702-013 --docker-context desktop-linux
```

The case provisions two Kind nodes and uses the node image from the Kind
v0.32.0 release. It exercises the image's stock kindnet NetworkPolicy implementation. It places the fixture clients on the control
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
- [Kind v0.32.0 and the pinned node image](https://github.com/kubernetes-sigs/kind/releases/tag/v0.32.0)
- [Versioned kindnetd implementation](https://github.com/kubernetes-sigs/kind/blob/v0.32.0/images/kindnetd/cmd/kindnetd/main.go)
- [NIST SP 800-53](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)

## Verify an adopting implementation

1. Inventory enrolled tenant namespaces, label owners, node pools, policy
   plugin and version, address families, shared-service paths and exceptions.
   Verify the plugin actually applies the policy on the tested dataplane.
2. Confirm default-deny ingress and egress applies when each tenant namespace
   is created and remains in force after permitted changes. Test the specific
   allow rules and corresponding out-of-scope flows from Pods on different nodes.
3. Repeat on both address families where supported. Assess DNS, host-network,
   node, external routes and application-layer policy using their own controls.
   Retain grants, revisions, timestamps, exception ownership and restoration evidence.
