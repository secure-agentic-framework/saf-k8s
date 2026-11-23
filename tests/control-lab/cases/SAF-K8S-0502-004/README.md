# SAF-K8S-0502-004 — CNI plugin hardening and lifecycle management

Run from the framework root:

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0502-004 --docker-context desktop-linux
```

Requires Helm 3.17, Kind v0.32.0 and a kernel supported by Cilium. The case uses an isolated Kubernetes v1.36.1 cluster and verifies the official Cilium 1.20.5 chart and workload image digests. The test deliberately submits an invalid readiness value to its own Helm release.

- **Permitted.** The approved values and pinned agent and operator permit a synthetic in-cluster Service request.
- **Red.** With atomic rollback disabled, the API rejects the readiness threshold and Helm leaves the new revision failed. The case manually restores the approved baseline before the second trial.
- **Green.** With atomic rollback enabled, the same API rejection creates a failed revision followed by a deployed rollback. The approved values and workload image pins are restored. The existing client reaches the same marker through the in-cluster Service.

This checks a Helm configuration rollback and the lab connectivity check. Collect independent evidence for deployed hardening approvals, patch and advisory response, managed provider SLAs, persistent CRD and state migrations, and production change controls.

[Cilium v1.20 Kind installation](https://docs.cilium.io/en/v1.20/installation/kind/) · [Helm v3 upgrade](https://helm.sh/docs/v3/helm/helm_upgrade/) · [Kubernetes v1.36 workload probes](https://v1-36.docs.kubernetes.io/docs/concepts/configuration/liveness-readiness-startup-probes/)
