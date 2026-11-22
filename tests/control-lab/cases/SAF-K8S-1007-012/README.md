# SAF-K8S-1007-012 — Synthetic AI infrastructure compatibility gate

This case runs on the supervisor's disposable, digest-pinned Kind Kubernetes v1.36.1 cluster. It creates five low-resource case-owned mock Deployments for the component roles named in the pinned control: GPU driver, CUDA toolkit, AI operator, device plugin, and serving framework. All run the same digest-pinned general-purpose Python sleep process; the role and version labels are inert metadata. No GPU, vendor component, model-serving software, or model is installed.

The case reads actual Kubernetes API discovery (`/api` and `/apis`) and actual Deployment objects through the API. It compares that observed inventory to `fixtures/compatibility-matrix.json`. The matrix deliberately uses reserved `SYNTH-*` identifiers and declares itself synthetic-only. It is an executable local decision fixture, not a vendor matrix or a compatibility claim.

## Expected outcomes

- **Positive:** the API server reports Kubernetes v1.36.1; `apps/v1` is served; and all five zero-replica mock Deployments have a digest-pinned template and match the fixture's synthetic baseline.
- **Red:** the candidate requiring synthetic dependency versions `*-02` is blocked because those values do not match the observed Deployments. The blocked candidate is not applied.
- **Green:** the candidate whose synthetic requirements match the observed inventory is permitted. The case updates only the serving-framework Deployment's metadata annotation, then reads the Deployment inventory again to confirm the new synthetic version and unchanged workload template, UID, other component metadata, and served API inventory.

Raw, bounded API and decision observations are written to `compatibility-governance.raw.json` in the run evidence directory. It contains no credentials or model data. The matrix does not come from an external feed, and the case contacts no external target.

## Real source claims and limits

The version-specific Kind v0.32.0 release identifies the Kubernetes v1.36.1 node image and its digest. Kubernetes v1.36 documentation describes `/api` and `/apis` discovery as the source of served group versions and resources; this case records group-version discovery and checks for `apps/v1`. Those are the only real compatibility-related claims exercised here. The `apps/v1` Deployment API is used for the mock resources.

The pinned control does not specify a vendor, SKU, driver/CUDA/operator/device-plugin/serving-framework versions, compatibility source of truth, freshness policy, runtime validation procedure, security gate, rollback policy, or approval workflow. Accordingly, this case does not claim that any real GPU, CUDA, operator, device plugin, serving framework, Kubernetes release, or model version is compatible. It also does not validate driver loading, GPU scheduling, CUDA execution, model quality, security regressions, coordinated production rollout, or real change approval. These claims remain unresolved for a source-backed production control test.

## Official primary sources

- [Kind v0.32.0 release](https://github.com/kubernetes-sigs/kind/releases/tag/v0.32.0) — identifies the default Kubernetes v1.36.1 node image and its digest.
- [Kubernetes v1.36 API discovery documentation](https://v1-36.docs.kubernetes.io/docs/concepts/overview/kubernetes-api/) — documents `/api` and `/apis` discovery and the served group/version inventory.
- [Kubernetes v1.36 Deployments](https://v1-36.docs.kubernetes.io/docs/concepts/workloads/controllers/deployment/) — defines the Deployment workload API used by the mock inventory.
- [Docker Official Python image digest record](https://hub.docker.com/layers/library/python/3.13-slim/images/sha256-a7cb177dc60dfa77b223192cd0d9e6ce1aac7cf9a569023d68e7c91b6371a718?tab=layers) — records the `python:3.13-slim` manifest digest used by the mock workload.
