# Argo CD reconciliation freshness

Run from the SAF-K8S framework checkout on a fresh Kind cluster.

```sh
python3 tests/control-lab/cases/SAF-K8S-0606-031/stalled/run.py --docker-context desktop-linux
```

The case uses Argo CD v3.6.1 with a case-owned Git repository and fixture
deployment. A namespaced reader checks the Application using the Kubernetes
API. Prometheus observes its reconciliation timestamp as well as native Argo
CD health metrics. The test observes three advancing timestamps, disables
periodic polling, and verifies Alertmanager delivers the exact freshness
alert while native Healthy/Synced metrics and the existing Ready workload
remain available. Re-enabling polling advances the timestamp and resolves
the alert through the same receiver.

This checks periodic reconciliation, delivered alerting, and recovery for
one application with pinned components. Production alert routing, polling
and webhook coverage, and controller integrity require their own evidence.
