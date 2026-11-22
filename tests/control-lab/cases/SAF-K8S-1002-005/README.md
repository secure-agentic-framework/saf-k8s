# SAF-K8S-1002-005 — Metrics API authorization

```sh
python3 lab.py test SAF-K8S-1002-005 --docker-context desktop-linux
```

From the framework checkout, use `python3 tests/control-lab/lab.py` with the same arguments. A fresh Kubernetes v1.36.1 Kind cluster hosts Prometheus and Prometheus Adapter v0.12.0, pinning component images and using case-owned aggregation certificates.

The test starts with an authenticated reader that has no metric grant and receives HTTP 403. Namespaced roles then allow each reader to retrieve its own exact custom and external metric samples. Direct cross-namespace reads and a cluster-scope custom metric request receive HTTP 403. An explicitly shared external metric returns both synthetic series through each authorized namespaced request. Prometheus reads only the two fixture namespaces for Pod discovery.

The API server's configured audit policy logs allowed and denied custom metric requests by Audit-ID. Its explicit external metrics exclusion leaves allowed and denied external requests absent from that backend. Production controller identities, approved sharing, deployed discovery, and audit retention require separate evidence.

[Prometheus Adapter v0.12.0 external metrics](https://github.com/kubernetes-sigs/prometheus-adapter/blob/v0.12.0/docs/externalmetrics.md) · [Kubernetes v1.36 audit](https://v1-36.docs.kubernetes.io/docs/tasks/debug/debug-cluster/audit/) · [Metrics Server aggregate role](https://github.com/kubernetes-sigs/metrics-server/blob/v0.8.1/manifests/base/rbac.yaml)
