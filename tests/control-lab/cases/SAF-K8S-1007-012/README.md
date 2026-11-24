# SAF-K8S-1007-012 — AI infrastructure compatibility decision gate

Run from the SAF-K8S framework root.

```sh
python3 tests/control-lab/lab.py test SAF-K8S-1007-012 --docker-context desktop-linux
```

This case runs on the supervisor's disposable, digest-pinned Kind Kubernetes v1.36.1 cluster. It creates five low-resource case-owned mock Deployments for the component roles named in the pinned control: GPU driver, CUDA toolkit, AI operator, device plugin, and serving framework. Their templates specify the same digest-pinned general-purpose Python sleep process; all five inventory Deployments remain at zero replicas, and role/version labels are inert metadata. No GPU, vendor component, model-serving software, or model is installed.

The case reads actual Kubernetes API discovery (`/api` and `/apis`) and actual Deployment objects through the API. It compares that observed inventory to `fixtures/compatibility-matrix.json`. The matrix deliberately uses reserved `SYNTH-*` identifiers and declares itself synthetic-only. It is an executable local decision fixture, not a vendor matrix or a compatibility claim.

## Expected outcomes

- **Positive:** the API server reports Kubernetes v1.36.1; `apps/v1` is served; and all five zero-replica mock Deployments have a digest-pinned template and match the fixture's synthetic baseline.
- **Red:** the candidate requiring synthetic dependency versions `*-02` is blocked because those values do not match the observed Deployments. The blocked candidate is not applied.
- **Green:** the candidate whose synthetic requirements match the observed inventory is permitted. The case updates only the serving-framework Deployment's component-version annotation, then reads the inventory again to confirm the new synthetic version, unchanged workload template and target UID, unchanged other component versions and target's other annotations, and unchanged served API inventory.

The case supplies a synthetic approval record containing the complete proposed
component tuple, a five-step ordered change sequence, the change ID, image and
three named check records: `functional.synthetic-marker-and-ready`,
`security.native-admission-denies-mismatch`, and
`reliability.stale-resource-version-no-mutation`. Each record is explicitly
marked `synthetic-pass`. Admission compares hashes of the tuple, sequence and
check records, as well as the matrix digest, change ID, image and release
marker. This is self-issued fixture data; it does not establish an independent
approver, real check provenance, or a real component version.

The ValidatingAdmissionPolicyBinding selects only the labeled `saf-test`
namespace; the policy also requires the exact namespace, case ownership label,
and Deployment name `saf-1007-012-approved-workload`. At Kubernetes admission the case
exercises a missing approval parameter, stale change sequence, mismatching
component tuple, and the accepted approval. The first three are denied and
leave no Deployment; the accepted record creates a CPU-only synthetic
Deployment whose release marker and Ready state are read back. An update with
a stale matrix annotation is denied without changing the admitted receipt.
Separately, the metadata-only compatibility patch uses a JSON Patch test on the
observed `resourceVersion`; a deliberately advanced resource version rejects
the stale patch while preserving the component version and Deployment UID.

The case writes API and decision observations to
`compatibility-governance.raw.json` in the run evidence directory. The case
collects no Secret objects or model payloads. The matrix is local and
synthetic-only, and the case logic contacts no vendor or compatibility feed.

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
3. Approve the exact tuple, artifacts, ordered change sequence, canary,
   recovery path, and named functional, security and reliability checks.
   Separate application deployment
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

The Kubernetes fixture exercises the governance handoff using self-issued
synthetic component identities and approval data, and a CPU workload. Its
admission checks and marker/Ready observations prove only those fixture
behaviors. It does not prove vendor compatibility, hardware, CUDA, GPU runtime,
or serving behavior. Adopters must retain independent approval provenance and
their real functional, security, reliability, and hardware evidence in SAF-K8S
control validation.

## Official primary sources

- [Kind v0.32.0 release](https://github.com/kubernetes-sigs/kind/releases/tag/v0.32.0) — identifies the default Kubernetes v1.36.1 node image and its digest.
- [Kubernetes v1.36 API discovery documentation](https://v1-36.docs.kubernetes.io/docs/concepts/overview/kubernetes-api/) — documents `/api` and `/apis` discovery and the served group/version inventory.
- [Kubernetes v1.36 Deployments](https://v1-36.docs.kubernetes.io/docs/concepts/workloads/controllers/deployment/) — defines the Deployment workload API used by the mock inventory.
- [Kubernetes v1.36 ValidatingAdmissionPolicy](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/) — ConfigMap parameters and fail-closed binding.
- [Kubernetes v1.36 GPU scheduling](https://v1-36.docs.kubernetes.io/docs/tasks/manage-gpus/scheduling-gpus/) — vendor drivers, device plugins, and resource use.
- [NVIDIA GPU Operator 25.10 platform support](https://docs.nvidia.com/datacenter/cloud-native/gpu-operator/25.10/platform-support.html) — example of a release-specific compatibility matrix.
- [NVIDIA CUDA Toolkit 12.9 release notes](https://docs.nvidia.com/cuda/archive/12.9.0/pdf/CUDA_Toolkit_Release_Notes.pdf) — example of a version-specific driver compatibility boundary.
