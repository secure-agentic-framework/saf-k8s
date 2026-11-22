# SAF-K8S-1007-010 — Target-version API compatibility preflight

Run with the control lab supervisor after reviewing the case snapshot. The standard runner creates one disposable Kind cluster at Kubernetes v1.36.1 using `kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5`. This case does not create another cluster or contact a remote target.

The preflight reads the Kubernetes server's exact `gitVersion` and API discovery for `policy`. It compares that live discovery to an offline synthetic mock-operator inventory. The inventory's pre-migration PodDisruptionBudget dependency is `policy/v1beta1`; the case records the missing group version from discovery and does not submit a request to the absent API. The repaired request uses `policy/v1` and is checked with server-side dry-run, so no PDB or workload is started. The PDB selector names only a reserved synthetic label and matches no deployed workload.

A small local gate function models promotion approval. It denies when evidence is missing, permits only when compatibility evidence matches the exact requested target version, and denies a version mismatch. It records a mock decision only; it does not invoke an upgrade or production system. The case also installs one synthetic `apiextensions.k8s.io/v1` CRD and one namespaced mock custom resource, then reads them back through the target API. No operator controller, Pods, model, training job, inference service, GPU, Secret, external API, real feed, or real target is used.

Raw evidence consists of the target version, API discovery documents, fixture-derived compatibility assessment, and the synthetic CRD/custom resource. The artifacts are written to the lab evidence directory and contain no credentials or Secrets.

## Checks and coverage

- **Red:** live discovery identifies the synthetic operator's declared `policy/v1beta1` dependency as unavailable; mock promotion is denied when compatibility evidence is absent.
- **Green:** exact target `v1.36.1` is observed; the repaired `policy/v1` resource is discovered and accepted by server-side dry-run; a matching evidence record permits the mock gate while a different requested target is denied.
- **Positive:** target accepts the synthetic CRD and custom resource; a complete matching evidence record permits the mock promotion decision.

This supports only a finite API-discovery and admission-acceptance example on one exact Kubernetes target version. It does not validate a real operator's client code or release, conversion webhooks, stored custom-resource migration, admission webhook behavior, operator reconciliation, training or inference paths, GPU scheduling, policy enforcement, performance, multi-version compatibility, cluster upgrade behavior, or production rollout integration. The target version and workload inventory are synthetic case inputs. Whether actual organization workloads have complete compatibility evidence remains unresolved until their owners supply versions, manifests, CRDs, webhooks, and workflow tests. Production upgrade-gate enforcement is not proven by this mock gate.

## Primary references

- [Kubernetes Deprecated API Migration Guide](https://kubernetes.io/docs/reference/using-api/deprecation-guide/) states that `policy/v1beta1` PodDisruptionBudget stopped being served in v1.25 and identifies `policy/v1` as its migration API. It also documents the semantic difference for an empty selector; this fixture uses a non-empty selector.
- [Kubernetes API discovery](https://kubernetes.io/docs/concepts/overview/kubernetes-api/) describes discovery documents for the APIs served by a cluster.
- [Kubernetes Custom Resources](https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/) and [CRD versioning](https://kubernetes.io/docs/tasks/extend-kubernetes/custom-resources/custom-resource-definition-versioning/) describe CRD-backed APIs and served/storage versions. The single synthetic version here does not exercise conversion or stored-version migration.
- [Kind Quick Start](https://kind.sigs.k8s.io/docs/user/quick-start/) documents selecting a Kubernetes node image by version and digest. The [official Kind v0.33.0 release](https://github.com/kubernetes-sigs/kind/releases/tag/v0.33.0) lists the exact v1.36.1 node image digest used by the runner.

The mock promotion gate persists an immutable receipt only on acceptance. The
missing-evidence and wrong-version comparators are also checked against the
API to confirm there is no approved receipt. A malformed dry-run custom object
exercises the target’s required-field validation.
