# SAF-K8S-0901-008 — Training worker network isolation

This case exercises the Kubernetes NetworkPolicy portion of the pinned control
on a disposable, single-node Kind Kubernetes v1.36.1 cluster. It requires Kind
v0.32.0 and its bundled kindnet policy implementation. The cluster node and all
workload Pods use digest-pinned images. The case does not install another CNI.

Before a policy exists, a synthetic worker Pod reaches harmless fixed-marker
HTTP listeners in both an authorized fixture namespace and a different,
unapproved fixture namespace. The case then applies a native egress
NetworkPolicy selecting only the labeled training worker. It allows IPv4
TCP/8080 only to a Pod with the authorized fixture label inside a namespace
with the authorized namespace label. The worker must still reach that listener
and must fail to reach the peer in the other fixture namespace. Separate
positive-control Pods, which the policy does not select, must reach their own
fixed-marker listener both before and after policy installation.

Checks require two consecutive observations and verify the exact fixed marker
on successful HTTP requests. The policy object is read back from the Kubernetes
API and compared with the expected selector, namespace selector, protocol, and
port. Raw JSON evidence records versions, image references, policy selectors,
synthetic pod IPs, path outcomes, and the fixed markers' match results. It
contains no tokens, Secret data, credentials, request bodies, real workload
content, or external addresses.

## Claim review and limits

Kubernetes documents NetworkPolicy as a pod-level, layer 4 control whose
enforcement depends on the network plugin. This case verifies the native
NetworkPolicy behavior on the pinned Kind v0.32.0 bundled kindnet profile. It
demonstrates a worker-scoped, namespace-and-pod-labeled egress allowlist for a
single synthetic TCP service, with a cross-namespace denied peer and an
independent positive path.

The control's general claims about distributed training, native transport
encryption limitations, NCCL, RDMA/InfiniBand, P_Keys, VLAN/fabric segmentation,
and lateral movement in production are not verified here. The single-node
fixture has no GPU, training framework, real gradients, production namespace,
multiple nodes, network fabric, encryption setting, admission workflow, or
operational policy deployment. It does not measure broad lateral-movement
resistance or test UDP, SCTP, DNS, IPv6, node/host traffic, or service-mesh
behavior. A successful fixture run is evidence only for the paths and profile
listed above; it does not establish enforcement by another CNI or fabric.

## Sources

- [Kubernetes v1.36 Network Policies](https://v1-36.docs.kubernetes.io/docs/concepts/services-networking/network-policies/) — selectors, additive policy behavior, and plugin enforcement prerequisite.
- [Kind v0.32.0 release](https://github.com/kubernetes-sigs/kind/releases/tag/v0.32.0) — Kubernetes v1.36.1 node image digest and release profile.
- [Kind configuration](https://kind.sigs.k8s.io/docs/user/configuration/) — bundled kindnet networking implementation.
- [Kind NetworkPolicy support in bundled kindnet](https://github.com/kubernetes-sigs/kind/releases/tag/v0.24.0) — upstream release notes for native NetworkPolicy support.
- [BusyBox official image](https://hub.docker.com/_/busybox) — source of the digest-pinned BusyBox image reference used by the lab fixtures.
