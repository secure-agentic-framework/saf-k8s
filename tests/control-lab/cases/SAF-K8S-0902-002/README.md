# SAF-K8S-0902-002 — Model loading integrity verification

This draft case targets a fresh disposable Kind Kubernetes v1.36.1 cluster. The case runner supplies the digest-pinned Kind node image. The only artifact is an immutable ConfigMap containing one public synthetic marker string; the mock serving process is a local fixture and exposes no Service or external endpoint.

The reviewed local control snapshot is `control.md`, SHA-256 `a3c7167a99d5f62c60d44cd40b40b4e1630f212ad5177bfd366899b83db40196`.

The case creates two digest-pinned Pods around the same bytes:

- **Red:** the BusyBox init container receives a fixed, deliberately nonmatching SHA-256 digest. The check requires its exact `DIGEST_MISMATCH` record and exit code 42, a Failed Pod, an app container still waiting with zero restarts, and no serving-container start.
- **Green:** the init container receives the fixture’s fixed matching SHA-256. It reports `DIGEST_VERIFIED`; the Python mock becomes Ready and logs the marker it read at startup.
- **Positive:** API-observed `volumeMount.readOnly`, the mock’s `/proc/self/mountinfo` read-only observation, and a write attempt failing with Linux `EROFS` (errno 30) are checked. A different Pod then reads and hashes the ConfigMap bytes independently; its marker and digest must still match the fixture. The mock has an in-Pod HTTP readiness endpoint so Kubernetes can report serving readiness; no Service or external endpoint is created or contacted.

Raw evidence is written to `model-integrity.raw.json`. It contains only the synthetic marker, digest, container status/log observations, readiness conditions, independent readback, and assertions. No credentials, Secret data, private keys, live model artifacts, feed data, or endpoint traffic are collected.

The control also calls for file integrity monitoring. This case does not claim monitoring coverage: one post-write independent readback is a point-in-time integrity observation, not continuous detection or alert delivery. Runtime replacement during inference, model cache integrity, registry/signature verification, production artifact acquisition, inference correctness, workload-specific startup controls, and monitoring/alert response remain separate scope.

Sources:

- [Kubernetes v1.36 init containers](https://v1-36.docs.kubernetes.io/docs/concepts/workloads/pods/init-containers/) — init containers must complete successfully before application containers start; failed init state is exposed in Pod status.
- [Kubernetes v1.36 volumes](https://v1-36.docs.kubernetes.io/docs/concepts/storage/volumes/) — a container volume mount can be made read-only with `volumeMounts[].readOnly`.
- [Kubernetes v1.36 probes](https://v1-36.docs.kubernetes.io/docs/concepts/configuration/liveness-readiness-startup-probes/) — readiness probes report when a container is ready to serve.
- [Docker Official Images Python metadata](https://github.com/docker-library/official-images/blob/master/library/python) and [BusyBox metadata](https://github.com/docker-library/official-images/blob/master/library/busybox) — image repositories and tags; this case additionally pins the exact image digests.
- [Kind node images](https://kind.sigs.k8s.io/docs/user/quick-start/#creating-a-cluster) — Kind documents the node image used to provision the Kubernetes version.

The control statement says “cryptographic signatures or digest checks.” This fixture tests only a local SHA-256 digest comparison before mock startup. It does not prove signer identity or artifact provenance. The rationale’s backdoored model scenario, model cache, real inference behavior, and continuous file integrity monitoring are not reproduced.
