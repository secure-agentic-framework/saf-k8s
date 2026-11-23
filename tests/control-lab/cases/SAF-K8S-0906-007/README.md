# SAF-K8S-0906-007: training-stage integrity fixture

## What the local case does

This case sends two benign, valid JSON fixtures through two deterministic transformations: (1) trim and lowercase each text/label while canonicalizing JSON, then (2) tokenize text into a small feature record. The expected SHA-256 digests for the approved input and both outputs are constants in `case.py` and `pipeline.py`, and are also mounted from an immutable trust ConfigMap. A separate Pod reads the final artifact and independently checks its digest and feature contents before emitting `accept` or `reject`.

The red check runs the alternate fixture with digest checks disabled and confirms that both transformations produce outputs. After a native Kubernetes ValidatingAdmissionPolicy is active, the same alternate stage record is submitted as a server-side dry run. The API server rejects it, and a follow-up read confirms that no ConfigMap was written. For the positive path, the runner first submits the exact approved stage records through admission. Only after both writes succeed does the worker publish its checked artifacts to the PVC; a separate Pod then reads the final artifact and emits the downstream decision.

## Run

Place this `case` directory next to `SAF-K8S-0908-001` in the authorized SAF harness. The runner imports `HERE.parent / "SAF-K8S-0908-001" / "case.py"` and calls its `load_runtime(lab)` to obtain the local Python fixture image. The harness must provide the `fixtures` module and a `lab` object implementing `create`, `kubectl`, `evidence`, and `check`.

The case creates and owns the `saf-test` namespace. It requires a Kubernetes version with `admissionregistration.k8s.io/v1` ValidatingAdmissionPolicy (Kubernetes 1.30+), a default PVC StorageClass, and one 1 GiB claim. Both PVC-consuming Pods are created before waiting for binding to support `WaitForFirstConsumer` StorageClasses.

The runner writes deterministic, sanitized JSON to `lab.evidence/training-integrity-observations.json`. It records digests, stage counts, admission results and the downstream decision; it does not record raw fixture text.

## Limits

This is a local lab demonstration using fixed synthetic records, one local pipeline, a fixture trust ConfigMap and native API-server admission. The admission policy compares stage bytes to embedded approved values; it does not calculate SHA-256 in CEL. The worker calculates SHA-256 and the separate consumer independently checks the final digest and contents. The case does not establish production trust-root management, authenticated producer identity, artifact-store immutability, concurrency behavior, full training-job isolation, monitoring coverage, or resistance to a privileged cluster administrator changing both policy and expected values. No production pipeline or training dataset is assessed.
