# SAF-K8S-0902-004 — Multi-model serving isolation and encryption

## Case design

This draft is a narrow mock-workload demonstration for the pinned control. It
creates two separately named and labeled Pods in `saf-0902-004`. Both run the
same small, case-owned Python fixture from the official digest-pinned Python
image. Each Pod receives its own memory-backed `emptyDir` with `sizeLimit: 8Mi`
mounted at `/dev/shm`. Each writes `model-cache.marker` at that identical path,
but stores a different fixed synthetic marker. The case records each Pod UID,
mount ID, filesystem type, tmpfs capacity, and marker. This makes the observed
boundary a Linux mount inside two distinct Pod sandboxes rather than an
assertion inferred from manifest text alone.

Each mock model also has its own memory request and limit. The fixture reads
`/proc/self/cgroup` and the matching memory controller files from its own
process context, then records the live current usage and limit. The API
resource values and live cgroup observation are retained together for each
Pod. Cgroup v2 uses `memory.current` and `memory.max`; cgroup v1 uses
`memory.usage_in_bytes` and `memory.limit_in_bytes`. The run will fail the
accounting check if it cannot read a bounded limit from the workload's own
cgroup.

Model A makes one fixed `GET /healthz` request to Model B through a
case-owned, cluster-internal `ClusterIP` Service. A one-day synthetic CA and
server/client certificates are generated in a temporary host directory for
the run. The endpoint requires a trusted client certificate; the client
validates the server chain and hostname. One request without a client
certificate must fail during TLS setup, then the same request with the
authorized test identity must return a fixed health marker. Server event logs
record only the fixed path and authenticated client common name; HTTP request
lines, addresses, headers, payloads, and TLS key material are not written to
case evidence.

## Run and evidence

The supervisor should run the case using the lab's ordinary disposable Kind
runner, then independently repeat it from a fresh cluster:

```sh
python3 lab.py test SAF-K8S-0902-004 --docker-context desktop-linux
```

The authoring draft has not been run. Do not treat the expected outcomes below
as observed results. The runner requires local `openssl` to generate the
ephemeral synthetic certificate hierarchy. The case itself makes no request
outside its cluster; the pinned official workload image must be available to
the Kind node (a cold image pull may require the supervisor's normal image
preparation).

The case writes `image-lock.raw.json` and `isolation-accounting.raw.json` in
the run evidence directory. They contain pinned image references, Kubernetes
version, Pod UIDs, resource values, cgroup counters, bounded mount details,
fixed markers, client result classes, and the fixed authenticated server
event. The evidence does not contain Secrets, certificate/private-key bytes,
kubeconfig contents, or arbitrary request data. The runner's ordinary
`commands.log` records the temporary file paths passed to `kubectl` and
OpenSSL, not file contents.

## Expected independently observable outcomes

| Phase | Expected observation |
| --- | --- |
| Positive | Kubernetes reports the two case-owned Pods with distinct UIDs and their configured memory requests and limits. |
| Positive | Each workload reports a nonzero current usage and a finite memory limit from its own cgroup matching its declared container limit. |
| Green | Both workloads report tmpfs mounted at `/dev/shm`, an 8Mi-or-smaller capacity, the same filename, and their distinct expected marker; their Pod UIDs and Linux mount IDs differ. |
| Red | The Model B TLS endpoint rejects the Model A request when the client omits its certificate. |
| Positive | Model A receives the exact synthetic `/healthz` marker over TLS, and Model B records the fixed path with authenticated client CN `model-a`. |

The red check is a negative authentication test against a controlled mock
endpoint. It does not represent an observed vulnerable deployment. The green
check is based on runtime observations inside the two Linux Pod mount
namespaces, not on the `emptyDir` declarations alone. Memory accounting is
container cgroup accounting; it is not a per-model GPU utilization or GPU
memory measurement.

## Scope and unresolved source claims

This case can provide evidence for only these behaviors in the observed
disposable Kind v1.36.1 environment:

- two distinct Pods have separate, explicitly bounded Linux tmpfs mounts at
  the same pathname, and their same-named benign files retain different
  contents;
- Kubernetes-stored memory requests and limits correspond to finite live
  accounting values read from each fixture process's own Linux cgroup; and
- one ordinary request between the case-owned mock Pods uses server
  certificate validation and mandatory client-certificate authentication.

It does **not** run ModelMesh Serving, Triton, KServe, a model server, a model
artifact, GPU workload, or a production service mesh. The label “model” is
only fixture metadata. The two Pods are independent mock workloads, not
co-located models inside a real multi-model serving runtime. Therefore this
case does not prove ModelMesh tenancy/isolation, Triton multi-model behavior,
or actual deployed mesh policy and coverage.

GPU memory allocation, MIG partitioning, vGPU isolation, GPU metrics, and
interference between real inference models remain unverified. CPU/memory
requests and limits plus host/container cgroup counters do not establish GPU
memory boundaries or per-model GPU accounting. Kubernetes `emptyDir` on
`medium: Memory` demonstrates a Pod-scoped tmpfs in this Linux fixture; it
does not prove isolation for an application that deliberately mounts or
shares memory through another mechanism. This is not an attempt to access
another Pod's mount or process memory.

The request checks one path and one case-owned Service in one cluster. It
does not establish TLS on external inference ingress, every internal call,
service-mesh sidecars, certificate issuance/rotation/revocation, policy
coverage, key custody, traffic capture resistance outside the tested
connection, or production identity mapping. There is no `NetworkPolicy`
assertion, no deployed-mesh assertion, and no attempt to bypass controls.
Only the fixed synthetic `/healthz` response is sent; no model input,
inference output, credential, user data, feed, or external target is used.

The control rationale's general statement that a co-located process can read
another model's shared memory is not validated by these separate-Pod fixtures.
The case instead demonstrates separate Pod-owned tmpfs instances for two
distinct mock workloads. Any broader source claim about shared-memory leakage,
resource starvation, GPU memory, model mesh, or end-to-end TLS across all
traffic paths requires separate evidence on the actual runtime and deployment.

## Fixtures and image pins

`fixtures/workload.py` implements only three fixed functions: create/read the
case-specific benign marker, report Linux mount/cgroup observations, and
serve/request one fixed health route over TLS. It does not accept arbitrary
commands, destinations, payloads, paths, or fixture identifiers. The only
runtime destination is the case-owned `model-b.saf-0902-004.svc` Service.
Certificates are generated at runtime into a private temporary directory and
are removed when the case finishes.

- Kind node: `kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5`, matching the [Kind v0.32.0 release](https://github.com/kubernetes-sigs/kind/releases/tag/v0.32.0).
- Workload: `docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90`, from the [Docker Official Images Python metadata](https://github.com/docker-library/official-images/blob/master/library/python).

## Official primary references

- [Kubernetes v1.36 resource management for Pods and containers](https://v1-36.docs.kubernetes.io/docs/concepts/configuration/manage-resources-containers/) — requests, limits, and cgroup behavior.
- [Kubernetes v1.36 volumes](https://v1-36.docs.kubernetes.io/docs/concepts/storage/volumes/) — Pod lifecycle and memory-backed `emptyDir` tmpfs behavior, including that tmpfs data counts against memory.
- [Kubernetes Services](https://kubernetes.io/docs/concepts/services-networking/service/) — `ClusterIP` is cluster-internal.
- [Linux kernel cgroup v2 documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html) — meanings of `memory.current` and `memory.max`.
- [Python 3.13 `ssl` documentation](https://docs.python.org/3.13/library/ssl.html) — certificate verification, hostname checking, and `CERT_REQUIRED` for server-side client certificate authentication.
- [OpenSSL `req` documentation](https://docs.openssl.org/master/man1/openssl-req/) — temporary X.509 test certificate generation.

A fixed 1 MiB accounting sample checks the writing model's cgroup charge and
confirms the peer's charge and marker remain scoped to its own workload.
