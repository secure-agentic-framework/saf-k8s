# SAF-K8S-0905-054 — Protect model downloads with namespace egress policy

Run `python3 tests/control-lab/lab.py test SAF-K8S-0905-054 --docker-context desktop-linux` from the framework checkout.

The same client downloads inert model JSON from an approved in-cluster proxy, a case-owned in-cluster hub, and a case-owned off-cluster hub on a disposable internal Docker bridge. The native NetworkPolicy limits all Pods in the protected namespace to the labeled proxy and CoreDNS. Both denied endpoints remain reachable from an independent namespace. The runner records status and exact allowed bytes, confirms DNS remains functional, and cleans up the isolated bridge.

This case checks destination isolation for the reviewed network topology. Verify real public hub destinations, trusted proxy upstream policy, cloud egress, production deny telemetry, and any host or node access paths separately. Kubernetes NetworkPolicy expresses network destinations using selectors and CIDRs.

- [Kubernetes 1.36 NetworkPolicy](https://v1-36.docs.kubernetes.io/docs/concepts/services-networking/network-policies/)
- [Kubernetes 1.36 DNS](https://v1-36.docs.kubernetes.io/docs/concepts/services-networking/dns-pod-service/)
