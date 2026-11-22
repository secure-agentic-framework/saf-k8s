# SAF-K8S-0902-005 — Authenticated two-cluster inference failover

Run `python3 lab.py test SAF-K8S-0902-005 --docker-context desktop-linux`.
The case needs two local Kind cluster slots and OpenSSL. A fixture router in
the primary cluster can reach a second owned Kind cluster through a NodePort
assigned by its API. No host port is published. The test verifies the peer
address corresponds to the owned node on the local Kind bridge.

Mutual TLS authenticates normal callers and the router. The router checks the
pinned model revision before requesting inference, and the backends require
that revision on inference requests. The case demonstrates primary operation,
healthy failover, cross-route rejection of an unassigned test identity, a
stale peer refused before inference, and primary recovery. Separate backend
logs record status and inference calls. Ephemeral certificates and keys are
excluded from receipts. Both clusters are removed.

Production ingress, multi-cluster service mesh, external authorization and
model registries, real workload routing, monitoring, and operations require
separate evidence.

- [Kind multiple clusters](https://kind.sigs.k8s.io/docs/user/quick-start/#creating-a-cluster)
- [Kubernetes NodePort](https://v1-36.docs.kubernetes.io/docs/concepts/services-networking/service/#type-nodeport)
