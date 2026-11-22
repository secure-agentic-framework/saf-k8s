# SAF-K8S-1002-001 — Metric endpoint authentication

```sh
python3 lab.py test SAF-K8S-1002-001 --docker-context desktop-linux
```

From the SAF-K8S checkout, run `python3 tests/control-lab/lab.py` with the same arguments. The fixture needs `htpasswd` with bcrypt support and reuses the TLS-enabled Metrics Server installer in SAF-K8S-1001-017.

In a fresh Kubernetes v1.36.1 Kind cluster, Prometheus initially serves a synthetic sample over TLS without asking for credentials. After HTTP Basic authentication is enabled, absent, malformed, and incorrect credentials receive HTTP 401. The authenticated reader still gets the same sample. A separate TLS exporter checks the credential Prometheus uses to scrape that sample.

The direct Metrics Server endpoint rejects anonymous and unauthorized requests with HTTP 403 and an invalid token with HTTP 401. The aggregated Metrics API returns HTTP 401 for absent or invalid credentials and HTTP 403 for an authenticated service account without permission. Both endpoints return the expected metrics to the authorized service account. The fixture validates TLS and stores only the responses and decisions.

Deployment evidence must cover the actual endpoint inventory, approved roles, custom and external metric APIs, managed Prometheus, kubelet endpoints, network controls and metric redaction.

[Prometheus HTTPS configuration](https://prometheus.io/docs/prometheus/latest/configuration/https/) · [Metrics Server v0.8.1 manifest](https://github.com/kubernetes-sigs/metrics-server/blob/v0.8.1/manifests/base/rbac.yaml)
