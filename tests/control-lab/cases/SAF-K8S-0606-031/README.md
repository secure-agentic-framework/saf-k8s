# SAF-K8S-0606-031 GitOps reconciliation monitoring

From the framework checkout, run the test on a fresh Kind cluster.

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0606-031 --docker-context desktop-linux
```

Argo CD v3.6.1 reconciles a pinned Git commit from a case-owned repository.
The test checks a Ready fixture workload, the resolved commit, and matching
Application status and controller metrics. It changes the requested manifest
path to a directory missing from that same commit. Argo CD must report a
`ComparisonError` and `Unknown` sync in both its API and metrics while the
live workload remains ready. Restoring the path clears the error and restores
healthy reconciliation to the exact commit.

The case demonstrates native Argo CD telemetry. Retention, alert delivery,
failure freshness, Flux coverage, and controller integrity need separate
evidence.

[Argo CD v3.6.1 metrics documentation](https://github.com/argoproj/argo-cd/blob/v3.6.1/docs/operator-manual/metrics.md)

The [retained monitoring test](monitor/README.md) exercises delivered alerts
and recorded reconciliation history from Prometheus and Alertmanager.
The [freshness test](stalled/README.md) checks alert firing and resolution
while the application continues to report Healthy and Synced.
