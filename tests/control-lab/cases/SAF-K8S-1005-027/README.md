# SAF-K8S-1005-027 — Scoped accelerator evidence preservation

Run with `python3 lab.py test SAF-K8S-1005-027 --docker-context desktop-linux`. The supervisor must execute the case on its fresh digest-pinned Kind v1.36.1 cluster and verify the result. This draft has not been run.

## Control review

The pinned statement and objective cover several materially different evidence sources: Kubernetes allocation metadata, driver-reported device state, hardware telemetry, and volatile state lost during restarts or node recycling. The control does not define required fields, collection authority, timing, retention, custody, validation, or success criteria. This case makes a narrow, testable contribution: scoped API evidence binding and hashing, plus retention of exact bytes after deleting owned synthetic sources. It does not treat those mechanics as proof of a complete forensic procedure.

## Case behavior

The case creates a reserved example-domain `mock.saf-lab.example` v1 ResourceSlice, DeviceClass, and ResourceClaim. A scheduler-triggering Pod references that claim, allowing the native Kubernetes v1.36.1 API to expose a real `status.allocation` record for the synthetic device. No DRA driver or accelerator is installed. The allocation is Kubernetes scheduling metadata about a case-owned mock ResourceSlice; it is not evidence of physical hardware allocation or device access.

A separate tokenless, CPU-only Python fixture prints fixed synthetic telemetry. It accesses no device, host path, external feed, or target. Raw Kubernetes API objects, the API observed cluster/node identity, mock workload output, and clearly marked fixture telemetry form a seven-artifact bundle. The case checks missing evidence and digest tampering (red), accepts complete identity-bound evidence (green), writes the exact bundle to an immutable case-owned ConfigMap, removes only objects whose case/fixture labels and names match, and verifies the retained ConfigMap UID, byte-for-byte content, and SHA-256 (positive).

The runner retains `forensic-acquisition.raw.json` as raw case evidence. It contains no credentials, secret data, or raw request bodies. The immutable in-cluster evidence ConfigMap is retained through the case's source cleanup and is removed only when the supervisor deletes the disposable cluster.

## Coverage and limits

**Covered if the supervisor obtains a passing replay:** native v1 API readback for ResourceSlice, DeviceClass and scheduler-populated ResourceClaim allocation metadata; identity binding to the fresh cluster, namespace, node, object UIDs and pinned image references; fixed synthetic accelerator/device state and telemetry; artifact hashing and digest mismatch detection; safe source ownership checks; and exact evidence retention after source removal.

**Unresolved:** actual accelerator hardware, a production DRA/device driver, driver/kernel telemetry, volatile device state, node recycling or restart timing, device plugin-specific artifacts, hardware memory or disk acquisition, completeness of real incident evidence, production collection authority, external custody and chain of custody, durable evidence storage/retention, and whether this procedure reconstructs compromise or misuse. Kind's single node and synthetic `all`/capacity semantics are not hardware behavior. A scheduler-populated allocation only demonstrates Kubernetes API metadata when the ResourceSlice is synthetic. The CPU-only fixture is not an AI inference workload.

The scope is limited to synthetic defensive metadata, reserved placeholders and inert mock workloads. No Docker or Kubernetes command was run while drafting this case.

## Primary sources

- [Kubernetes v1.36 Dynamic Resource Allocation](https://v1-36.docs.kubernetes.io/docs/concepts/scheduling-eviction/dynamic-resource-allocation/) — ResourceSlice, ResourceClaim allocation flow, and API observability.
- [Kubernetes v1.36 Allocate Devices with DRA](https://v1-36.docs.kubernetes.io/docs/tasks/configure-pod-container/assign-resources/allocate-devices-dra/) — stable v1 API and workload claim reference pattern.
- [Kubernetes ResourceClaim v1 API](https://kubernetes.io/docs/reference/kubernetes-api/resource/resource-claim-v1/) and [ResourceSlice v1 API](https://kubernetes.io/docs/reference/kubernetes-api/resource/resource-slice-v1/).
- [Kind v0.32.0 release](https://github.com/kubernetes-sigs/kind/releases/tag/v0.32.0) — v1.36.1 node image digest. The runner uses this digest-pinned node image; the CPU fixture image is also pinned to a SHA-256 digest.
