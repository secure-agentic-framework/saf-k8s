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

The case demonstrates native Argo CD telemetry. The tests below cover
retention, alert delivery, stale reconciliation, Flux behavior, and controller
integrity in their stated scopes.

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

## Verify an adopting GitOps deployment

The 14-check reference covers the scoped Argo CD and Flux reconciliation paths.
The Argo release-integrity fixture verifies the approved signer, running
release chain, and configuration guard. Its separate monitoring and freshness
tests demonstrate delivered alerts, resolution and retained state history.
Use these paths as examples when verifying the adopting deployment.

### Monitoring and alert delivery

For every in-scope production controller/application, record the cluster and environment, controller/version, enrolled application identity, approved Git repository and revision, and the owner of the reconciliation thresholds and polling cadence. Independently observe the controller-native status/revision/freshness signal and its monitoring export. Retain time-bounded history for the approved retention period. Demonstrate the approved alert route by observing a controlled failed or stale reconciliation, delivered notification, owner acknowledgement/resolution, and recovery notification. Include the actual alert rule, destination/receiver identity, timestamps, and reviewer-approved sanitized event evidence. State exclusions and any monitoring gaps per environment.

### Release identity and configuration

For each authorized environment, inventory the GitOps controller components and compare the actually running image digests (not only tags or desired manifests) with the release approved for that environment. Preserve independent signature/provenance verification output and verify the expected signer/workflow/source identity against the organization's approved trust policy at promotion. Show the promotion gate rejected an unapproved release or identity. Compare effective controller configuration with an independently approved baseline; show an unauthorized configuration change is rejected and an approved change is applied by its authorized principal. Record reviewer, approval, environment, deployed digest/config revision, observation time, and rollback/recovery evidence. Apply this to Flux separately if Flux is deployed; the portable controller-integrity checks in the current receipt cover Argo CD only.
