# SAF-K8S-1007-012 — AI infrastructure compatibility decision gate

Run from the SAF-K8S framework root.

```sh
python3 tests/control-lab/lab.py test SAF-K8S-1007-012 --docker-context desktop-linux
```

This case runs on the supervisor's disposable, digest-pinned Kind Kubernetes v1.36.1 cluster. It creates five low-resource case-owned mock Deployments for the component roles named in the pinned control: GPU driver, CUDA toolkit, AI operator, device plugin, and serving framework. All run the same digest-pinned general-purpose Python sleep process; the role and version labels are inert metadata. No GPU, vendor component, model-serving software, or model is installed.

The case reads actual Kubernetes API discovery (`/api` and `/apis`) and actual Deployment objects through the API. It compares that observed inventory to `fixtures/compatibility-matrix.json`. The matrix deliberately uses reserved `SYNTH-*` identifiers and declares itself synthetic-only. It is an executable local decision fixture, not a vendor matrix or a compatibility claim.

## Expected outcomes

- **Positive:** the API server reports Kubernetes v1.36.1; `apps/v1` is served; and all five zero-replica mock Deployments have a digest-pinned template and match the fixture's synthetic baseline.
- **Red:** the candidate requiring synthetic dependency versions `*-02` is blocked because those values do not match the observed Deployments. The blocked candidate is not applied.
- **Green:** the candidate whose synthetic requirements match the observed inventory is permitted. The case updates only the serving-framework Deployment's metadata annotation, then reads the Deployment inventory again to confirm the new synthetic version and unchanged workload template, UID, other component metadata, and served API inventory.

Raw, bounded API and decision observations are written to `compatibility-governance.raw.json` in the run evidence directory. It contains no credentials or model data. The matrix does not come from an external feed, and the case contacts no external target.

The native extension uses a ConfigMap parameter for a ValidatingAdmissionPolicy
scoped to one owned Deployment. A stale matrix digest receives the exact API
denial and leaves no Deployment. The approved matrix digest, image and release
marker pass admission, a synthetic CPU workload starts, and its log and Ready
state confirm that the approved release reached a container.

## Verify your implementation

1. Identify the exact vendor, accelerator model, architecture, OS/kernel,
   Kubernetes/CRI, GPU partitioning mode, driver, CUDA runtime or toolkit,
   operator, device plugin, container toolkit, serving image and model. Record
   the resolved image digests and effective running versions. Pin the
   applicable release-specific support sources and their review time.
2. Compare the installed and proposed component tuples. Record supported ranges
   and limits for the selected vendor path, such as CUDA API and feature
   restrictions, OS or kernel prerequisites and separately managed components.
   Treat conflicting, missing or expired source evidence as unresolved.
3. Approve the exact tuple, artifacts, change order, canary, recovery path and
   named security and reliability checks. Separate application deployment
   authority from compatibility approval. Exercise the actual gate with
   missing, stale and matching evidence, and retain the verdict and observed
   workload revision.
4. In a compatible test environment, verify the driver loaded on the exact
   node, the device resource is allocatable and allocated to an authorized Pod,
   the workload uses the expected device and CUDA runtime, and an approved
   inference canary returns the expected response. Check isolation, failure
   handling and health before and after the change. Link this hardware evidence
   to the same tuple and change decision. A documentary source comparison and
   a successful in-cluster workload run supply distinct evidence.

The Kubernetes fixture exercises the governance handoff using synthetic
component identities and a CPU workload. The hardware evidence is tracked
in SAF-K8S control validation separately.

## Official primary sources

- [Kind v0.32.0 release](https://github.com/kubernetes-sigs/kind/releases/tag/v0.32.0) — identifies the default Kubernetes v1.36.1 node image and its digest.
- [Kubernetes v1.36 API discovery documentation](https://v1-36.docs.kubernetes.io/docs/concepts/overview/kubernetes-api/) — documents `/api` and `/apis` discovery and the served group/version inventory.
- [Kubernetes v1.36 Deployments](https://v1-36.docs.kubernetes.io/docs/concepts/workloads/controllers/deployment/) — defines the Deployment workload API used by the mock inventory.
- [Docker Official Python image digest record](https://hub.docker.com/layers/library/python/3.13-slim/images/sha256-a7cb177dc60dfa77b223192cd0d9e6ce1aac7cf9a569023d68e7c91b6371a718?tab=layers) — records the `python:3.13-slim` manifest digest used by the mock workload.

- [Kubernetes v1.36 ValidatingAdmissionPolicy](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/) — ConfigMap parameters and fail-closed binding.
- [Kubernetes v1.36 GPU scheduling](https://v1-36.docs.kubernetes.io/docs/tasks/manage-gpus/scheduling-gpus/) — vendor drivers, device plugins, and resource use.
- [NVIDIA GPU Operator 25.10 platform support](https://docs.nvidia.com/datacenter/cloud-native/gpu-operator/25.10/platform-support.html) — example of a release-specific compatibility matrix.
- [NVIDIA CUDA Toolkit 12.9 release notes](https://docs.nvidia.com/cuda/archive/12.9.0/pdf/CUDA_Toolkit_Release_Notes.pdf) — example of a version-specific driver compatibility boundary.
