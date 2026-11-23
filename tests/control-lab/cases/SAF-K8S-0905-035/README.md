# SAF-K8S-0905-035 — Roll back a degraded model canary

    python3 tests/control-lab/lab.py test SAF-K8S-0905-035 --docker-context desktop-linux

A restricted rollout-analysis Job samples the actual candidate endpoint and evaluates an error-rate and latency threshold. In the enabled cases, one Kubernetes API update records the decision and redirects the Service to stable. A separate observer verifies that the route serves the stable response. The disabled and healthy cases leave the candidate selected.

Production rollout time, thresholds, network behavior, model health, retention and multi-replica behavior require deployed evidence.

- [Kubernetes 1.36 Services](https://v1-36.docs.kubernetes.io/docs/concepts/services-networking/service/)
- [Argo Rollouts analysis semantics](https://argoproj.github.io/argo-rollouts/features/analysis/)
