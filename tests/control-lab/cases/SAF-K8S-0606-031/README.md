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

The case also runs Flux v2.9.0 using the existing SAF-K8S-0606-028 release
and Smart HTTP Git serving fixture. It checks the exact approved Git reference,
Flux source and Kustomization status, and the exported resource state from
kube-state-metrics v2.20.0. A missing path triggers an ArtifactFailed condition
and a fresh observed reconciliation request. Restoring the path reestablishes
Ready for the same approved revision. The previously applied test workload
remains available across both transitions.

The controller-integrity fixture verifies the Argo CD OCI image signature and
upstream SLSA source tag. It binds the ready controller, repository server, and API server container
image IDs to the verified OCI index. In this Kind runtime, containerd exposes
the index digest. The fixture also hashes the platform manifest and config and
matches the resulting layer chain to each running container snapshot parent. A scoped native admission policy rejects fixture configuration drift and
permits an approved service-account update to the designated ConfigMap entry.
This validates the fixture's controller configuration and upstream image
identity. Production signing authority and rollout gates require their own
evidence.
