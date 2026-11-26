# SAF-K8S-0606-029 — Retain GitOps package and version metadata

Run `python3 tests/control-lab/lab.py test SAF-K8S-0606-029 --docker-context desktop-linux` from the framework checkout.

Pinned Argo CD deploys two exact Git commits containing successive versions of a fixture Helm chart. The seven checks compare the resolved revisions, chart and workload versions, Ready Pods and runtime image digests. The test runner writes each immutable record after observing successful reconciliation. Both records remain readable after promotion. Kubernetes refuses a change to the earlier record. The retained run evidence includes the chart source identity, workload image and target namespace.

## Verify an adopted release ledger

1. Inventory every target cluster, environment, release path and package format. Record the controller and release-system versions, source commit or registry digest, chart or package version, deployed workload identity and the record owner. Include direct manifests, operators, Helm, OCI and model deployment formats where used.
2. Trace authoritative collection for each successful release. Match the controller's resolved revision or package digest to the deployed package or workload digest and exact environment. Inspect record-writer identity, access scope, retries and gaps.
3. Reconcile at least two successive releases, retrieving the first record after the second and checking both against observed sources and workloads. Include rollback and re-promotion where applicable.
4. Verify effective permissions, retention and pruning rules, backup and restore and independent retrieval during recovery. Identify any manual paths or unsupported environments and packages.
5. Where Annex IV technical documentation applies, reconcile relevant software or firmware records to the actual AI system and include its applicable version-update requirements.

- [Argo CD 3.6.1 Helm integration](https://github.com/argoproj/argo-cd/blob/v3.6.1/docs/user-guide/helm.md)
- [Regulation (EU) 2024/1689, Annex IV](https://eur-lex.europa.eu/eli/reg/2024/1689/oj/eng/pdf)
