# SAF-K8S-0101-016 — API server audit log backend delivery and durable storage

## Case behavior

The default cluster processes a synthetic ConfigMap create and patch with
auditing disabled. The configured cluster repeats the same requests with a
Metadata-only audit policy, blocking file delivery, size rotation, and an
explicit temporary host mount. The verifier finds the exact namespace,
resource, name, verb, stage and response code in the resulting audit event.
It stops only the owned API server container and waits for kubelet to recreate
it with a different container ID and a healthy API. The earlier event remains
searchable, and a second named request reaches the same file.

Only `Metadata` is requested by the policy. The verifier retains only selected
event metadata and does not log complete audit records. Fixtures and resources
are synthetic. Each run has a private output directory that is removed after
its audit cluster is deleted.

## Buffering and durability boundary

The Kubernetes v1.36 log backend defaults to blocking delivery; this case sets
`--audit-log-mode=blocking` explicitly. A successful matching line establishes
delivery to the mounted local file for these requests. The file survives an API
server container restart because it is outside the container writable layer.
That observation is not proof of filesystem flush behavior under host power loss,
storage failure, host loss, backend tamper protection, archival retention, or
search availability after cluster deletion. Durable production storage needs an
independently managed persistent volume or collector/archive with tested failure
and retention behavior.

The webhook backend is not exercised. Its batching mode buffers events
asynchronously, can drop events when its finite buffer overflows, and relies on
remote endpoint availability/retry semantics. The webhook's `blocking` and
`blocking-strict` modes have different request/failure semantics from the
default `batch` mode. A local file result does not establish webhook delivery,
durable webhook ingestion, or the semantics of a downstream SIEM. Provider
managed control planes also require provider-specific audit destinations,
delivery and retention evidence; kind does not establish any provider claim.

## Sources

- [Kubernetes v1.36 auditing: log and webhook backends, mounts, and buffering modes](https://v1-36.docs.kubernetes.io/docs/tasks/debug/debug-cluster/audit/)
- [Kubernetes v1.36 kube-apiserver flags](https://v1-36.docs.kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/)
- [Kubernetes v1.36.1 audit backend implementation](https://github.com/kubernetes/kubernetes/tree/v1.36.1/staging/src/k8s.io/apiserver/pkg/audit)

## Scope and pending evidence

- Profile: pinned by the lab harness to `kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5`.
- One synthetic ConfigMap path and one API server restart do not establish all-request policy coverage, sustained load behavior, power-loss durability, or managed-provider behavior.
