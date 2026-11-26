# SAF-K8S-0905-055 — Validate declared model source references

Run the case by ID from the framework checkout.

    python3 tests/control-lab/lab.py test SAF-K8S-0905-055 --docker-context desktop-linux

Three native policies check the same declared source fields at the Pod, ordinary workload template, and CronJob template paths. A named ConfigMap supplies exact approved HTTPS and OCI values. The case exercises six workload kinds, init containers, an update to a persisted zero-replica Deployment, rotation of a source URL, and fail-closed behavior after parameter deletion. Inputs are inert and source strings are never contacted.

Verify production namespace enrollment, parameter ownership, other application source lookup paths, and egress separately.

- [Kubernetes 1.36 ValidatingAdmissionPolicy](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)
- [Kubernetes 1.36 CEL](https://v1-36.docs.kubernetes.io/docs/reference/using-api/cel/)

## Controller coverage

The published 31-check fixture covers Pod, Deployment, StatefulSet, DaemonSet, Job and CronJob CREATE paths, their direct Pod templates, two explicit source environment names (`MODEL_SOURCE_URL`, `MODEL_SOURCE_OCI`), init containers, a persisted zero-replica Deployment UPDATE, allowlist rotation, and missing-parameter fail-closed behavior. All writes/denials apart from the stored zero-replica Deployment are server-side dry-run; source strings are inert and never resolved.

The fixture includes `ReplicaSet` (`apps/v1`) and legacy `ReplicationController` (`v1`) to the same template policy resource rules and existing red/green comparator loops. It reuses the exact harmless declared environment fields, dummy allowlist values, and server-side dry-run API requests. This adds six expected assertions: alternate source admitted before enrollment for both kinds, alternate denied after enrollment for both, and approved source still admitted for both. Expected total is 37 if executed. It creates no Pods and starts no workloads. The addition covers those two direct built-in controller-template API paths; it does not cover every CRD, every controller conversion, complete Pod creation paths, or actual model fetching.

## Exact source-field boundary

The VAP expressions inspect only `env[]` in normal and init containers, for variables named `MODEL_SOURCE_URL` and `MODEL_SOURCE_OCI`. For Pods they read `object.spec`; for Deployments, ReplicaSets, StatefulSets, DaemonSets and Jobs they read `object.spec.template.spec`; for CronJobs they read `object.spec.jobTemplate.spec.template.spec`. They require literal values and reject `valueFrom` for those named fields. They do not inspect container image references (the image here is just an inert test worker), `command`, `args`, ephemeral-container updates, mounted files/configuration, arbitrary environment names, application-side URI composition, custom resources, or runtime network access.


## Model-carrier image comparison

The catalog explicitly includes image references. This separate proposal governs only a standardized model-carrier container named `model-carrier` in Pod and Deployment normal/init-container specs. The exact image reference is stored in the existing namespace-scoped allowlist ConfigMap key `model_carrier_images`; it does not reinterpret the `oci` model-download URI key. The dedicated VAP compares the carrier container image field to that value. It leaves other containers' images unclassified and therefore admissible, including the dummy `ordinary-helper` image. This interface is valid only for deployments that standardize this name to mean “the container image is the model artifact/source.” A renamed carrier or model acquired from application configuration is outside this rule and must be mapped separately.

Two grouped checks cover the model-carrier image field. First, alternate carrier image references are admitted by the API before the dedicated policy. After policy activates, unapproved carrier images are denied for Pod and Deployment, approved carrier images remain admissible, and unrelated helper images outside the allowlist remain admissible. Total expected count is 39. Requests are server-side dry-run only, use `.test` placeholder references, start no Pods, and cause no image pulls. The previous 37 check behaviors are retained.

The model-carrier policy has its own namespaced parameter reference to the same ConfigMap, with a distinct `model_carrier_images` key and `parameterNotFoundAction: Deny`. It is deliberately scoped to Pod and Deployment only; the earlier source-field candidate separately covers other built-in workload templates and adds ReplicaSet/ReplicationController. Before adoption, extend the image-field policy to the actual carrier object kinds and verify API conversion and controller-created Pods.

## Adopter procedure

1. Inventory protected namespaces and every object route that can create Pods: direct Pods, all controllers in use (including ReplicaSets and any legacy ReplicationControllers), and CRDs/operators that materialize Pod specs.
2. For each model-serving/training application, identify exact fields that trigger acquisition: environment variables, command/args, mounted configuration and custom resources. Bind each field and source format to policy; test normal, init and any relevant ephemeral-container paths.
3. Enroll protected namespaces and protect policy, binding and allowlist parameters with separate authorization. Confirm fail-closed behavior for missing or malformed parameters.
4. Use server dry-run for approved and unapproved source values per governed object path. Where controller behavior matters, use a harmless controlled workload to verify its generated Pod and capture owner references; check denied updates leave stored objects unchanged.
5. Rotate the allowlist through an approved change, confirm newly approved values pass and removed values fail, and preserve policy version and admission evidence. Verify source authenticity and runtime egress independently.

## Authority

- [NIST SP 800-53 Rev. 5.1](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf): AC-21(1) authorized information-sharing decisions; AC-25 reference monitor requirements.
- [NIST SP 800-218 SSDF 1.1](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-218.pdf): PW.9.2 software default settings and administrator documentation.
- [Kubernetes v1.36 ValidatingAdmissionPolicy](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/), [ReplicaSet](https://v1-36.docs.kubernetes.io/docs/concepts/workloads/controllers/replicaset/), and [ReplicationController](https://v1-36.docs.kubernetes.io/docs/concepts/workloads/controllers/replicationcontroller/).
