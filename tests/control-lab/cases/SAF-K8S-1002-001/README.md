# SAF-K8S-1002-001 — Metric endpoint authentication

```sh
python3 lab.py test SAF-K8S-1002-001 --docker-context desktop-linux
```

From the SAF-K8S checkout, run `python3 tests/control-lab/lab.py` with the same arguments. The fixture needs `htpasswd` with bcrypt support and reuses the TLS-enabled Metrics Server installer in SAF-K8S-1001-017.

In a fresh Kubernetes v1.36.1 Kind cluster, Prometheus initially serves a synthetic sample over TLS without asking for credentials. After HTTP Basic authentication is enabled, absent, malformed, and incorrect credentials receive HTTP 401. The authenticated reader still gets the same sample. A separate TLS exporter checks the credential Prometheus uses to scrape that sample.

The direct Metrics Server endpoint rejects anonymous and unauthorized requests with HTTP 403 and an invalid token with HTTP 401. The aggregated Metrics API returns HTTP 401 for absent or invalid credentials and HTTP 403 for an authenticated service account without permission. Both endpoints return the expected metrics to the authorized service account. The fixture validates TLS and stores only the responses and decisions.

Before installing Metrics Server, the built-in view, edit, and admin roles lack the fixture resource metric grants. The installed system:aggregated-metrics-reader contributes get, list, and watch for metrics.k8s.io Pods and Nodes to all three roles. The original system:metrics-reader reference does not resolve. A namespaced RoleBinding to view lets each fixture account retrieve its own PodMetrics and returns HTTP 403 for the other namespace.

## Adopter verification

1. Inventory the deployed metrics endpoints and clients, including direct exporters, kubelets, aggregated APIs, custom and external APIs, and managed monitoring. Record which identities and network paths are authorized for each endpoint and what metric labels may be disclosed.
2. Verify TLS trust and expected service identity on each protected route. Use approved synthetic samples and adopter test identities to show that missing, invalid, and insufficient credentials are rejected as applicable, while the authorized principal can still read its intended metrics. Test direct backend access separately from aggregated and ingress paths.
3. For Kubernetes metrics resources, verify effective namespace and cluster grants and aggregation labels, including near-miss subjects and namespaces. For scrapes, retain the authenticated target identity, the actual consumer's identity and permitted labels, and the result after rotation or revocation. Redact credentials and sensitive labels from retained evidence.
4. Map access enforcement and service identification only to the verified approved readers and peers. Consider the AI RMF production-monitoring contribution only when the authorized metrics reach a named production-monitoring consumer and support its defined AI-system monitoring objective.

[Prometheus HTTPS configuration](https://prometheus.io/docs/prometheus/latest/configuration/https/) · [Metrics Server v0.8.1 manifest](https://github.com/kubernetes-sigs/metrics-server/blob/v0.8.1/manifests/base/rbac.yaml)
