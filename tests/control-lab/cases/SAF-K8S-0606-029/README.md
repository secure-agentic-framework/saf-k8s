# SAF-K8S-0606-029 — Retain GitOps package and version metadata

Run `python3 tests/control-lab/lab.py test SAF-K8S-0606-029 --docker-context desktop-linux` from the framework checkout.

The eight checks include both successful release hooks and the earlier no-hook comparison. Argo CD v3.6.1 reconciles three case-owned Git revisions: chart 1.0.0 without a record hook, the same chart version with a PostSync hook, and chart 1.1.0 with the hook. The no-hook step verifies that rendering alone creates no release record. Each successful PostSync Job reads only the exact Argo Application, release Deployment, Ready package Pod, and immutable source index, then creates one immutable release record. The writer checks the exact active sync operation and observes a Ready workload before writing each record. The runner then independently confirms the final Application sync status and compares both records with the resolved Git commit/tree and live workload image digest after promotion.

The hook runs as `saf-release-writer`. Its namespace Role grants exact source-index and Deployment reads, Pod listing, and ConfigMap creation. A separate Role permits reading only the named Argo Application. A ValidatingAdmissionPolicy constrains this identity's ConfigMap creates to the two named immutable fixture records and version labels. The writer uses only the projected service-account token in an in-process HTTPS request to the Kubernetes API. It never places the token in an argument, environment variable, output, command log, or evidence. Job output contains only a success/failure marker and release name. Jobs have a 90-second deadline, no retries, 10m/32Mi requests, and 100m/96Mi limits.

This is reference evidence for one Argo CD version, a case-owned Git Helm source and one disposable Kind cluster. It does not establish production ledger durability, external registry or OCI collection, other controllers/package formats, backup/restore, retention policy, or rollback/re-promotion workflow.

## Verify an adopted release ledger

1. Inventory every target cluster, environment, release path and package format. Record the controller and release-system versions, resolved source commit or artifact digest, deployed workload identity, and record owner. Include direct manifests, operators, Helm, OCI and model-deployment formats where used.
2. Trace the actual successful-release trigger and authoritative collector. Confirm that the hook/controller waits for the deployed resources to be healthy and binds the record to the exact source identity, workload digest, namespace, and cluster.
3. Reconcile at least two successive releases. Retrieve the first record after promotion and compare both records with independently observed deployed workloads. Include rollback and re-promotion where those paths are claimed.
4. Verify effective writer permissions, immutability, retention/pruning, backup and restore, independent retrieval during recovery, and any manual or unsupported paths.
5. Where Annex IV technical documentation applies, reconcile relevant software or firmware records to the actual AI system and its applicable version-update requirements.

- [Argo CD 3.6.1 sync phases and hooks](https://github.com/argoproj/argo-cd/blob/v3.6.1/docs/user-guide/sync-waves.md)
- [Argo CD 3.6.1 Helm integration](https://github.com/argoproj/argo-cd/blob/v3.6.1/docs/user-guide/helm.md)
- [Regulation (EU) 2024/1689, Annex IV](https://eur-lex.europa.eu/eli/reg/2024/1689/oj/eng/pdf)
