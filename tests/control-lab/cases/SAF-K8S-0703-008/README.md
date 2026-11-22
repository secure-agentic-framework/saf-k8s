# SAF-K8S-0703-008 — Idle telemetry and bounded reclamation

```sh
python3 lab.py test SAF-K8S-0703-008 --docker-context desktop-linux
```

Prometheus v3.16.0 scrapes the owned test service on Kubernetes
v1.36.1. The case first observes an 80% synthetic sample with no
matching idle alert and one target replica. It changes the sample
to zero. The alert enters pending while the fixture still has a
replica, then fires for exactly the test signal after the configured
hold. The lab sends a normal scale request only for the labeled
fixture while that alert is firing and verifies that its Pods
are gone while an independent protected Deployment remains ready.

The signal contains no device measurement. Real accelerator
utilization, signal ownership and accuracy, production policy
thresholds, configured automation, workflow safety, and the resulting
release of actual capacity require deployment evidence.

- [Prometheus v3.16.0](https://github.com/prometheus/prometheus/releases/tag/v3.16.0)
- [Prometheus alerting rules](https://prometheus.io/docs/prometheus/latest/configuration/alerting_rules/)
- [Kubernetes v1.36 Deployments](https://v1-36.docs.kubernetes.io/docs/concepts/workloads/controllers/deployment/)
