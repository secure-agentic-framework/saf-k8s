# SAF-K8S-0902-004 — Multi-model serving isolation and encryption

## Case design

This mock-workload demonstration for the pinned control creates two separately named and labeled Pods in `saf-0902-004`. Both run the
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
certificate must fail during TLS setup. A second client certificate is valid
under the same test CA but has a different URI peer identity; TLS completes,
and the endpoint must deny it before returning the health marker. The
authorized test identity must then receive the fixed health marker. Server
event logs record only the fixed path and the fixed synthetic URI peer identity; HTTP request
lines, addresses, headers, payloads, and TLS key material are not written to
case evidence.

## Run and evidence

The supervisor should run the case using the lab's ordinary disposable Kind
runner, then independently repeat it from a fresh cluster:

```sh
python3 lab.py test SAF-K8S-0902-004 --docker-context desktop-linux
```

The published control-lab and framework receipts record passed runs with seven
matched checks on separate disposable Kind clusters at catalog revision
`e36407042cfd3bc4969961e9136bfe8a1923b4e9`. The checks include a trusted but
unapproved synthetic peer being denied and one available, explicitly allowed
Model A-to-Model B `/healthz` route succeeding with server and client
certificate verification. That positive route is the only inference path in
this fixture: it is one case-owned internal ClusterIP Service, not evidence of
external ingress or every internal hop. See the [published verification
receipt](https://github.com/secure-agentic-framework/saf-k8s/blob/9213cf921cba88b60d3ebf4c50563835fa3e2ef0/tests/control-lab/verified/SAF-K8S-0902-004.json)
and the pinned [case source](https://github.com/secure-agentic-framework/saf-k8s/tree/9213cf921cba88b60d3ebf4c50563835fa3e2ef0/tests/control-lab/cases/SAF-K8S-0902-004).
The runner requires local `openssl` to generate the ephemeral synthetic
certificate hierarchy. The case makes no request outside its cluster; the
pinned official workload image must be available to the Kind node (a cold
image pull may require the supervisor's normal image preparation).

The case writes `image-lock.raw.json` and `isolation-accounting.raw.json` in
the run evidence directory. They contain pinned image references, Kubernetes
version, Pod UIDs, resource values, cgroup counters, bounded mount details,
fixed markers, client result classes, and the fixed authenticated server
event. The evidence does not contain Secrets, certificate/private-key bytes,
kubeconfig contents, or arbitrary request data. The runner's ordinary
`commands.log` records the temporary file paths passed to `kubectl` and
OpenSSL, not file contents.

## Receipt observations

| Phase | Recorded observation |
| --- | --- |
| Positive | Kubernetes reports the two case-owned Pods with distinct UIDs and their configured memory requests and limits. |
| Positive | Each workload reports a nonzero current usage and a finite memory limit from its own cgroup matching its declared container limit. |
| Green | Both workloads report tmpfs mounted at `/dev/shm`, an 8Mi-or-smaller capacity, the same filename, and their distinct expected marker; their Pod UIDs and Linux mount IDs differ. |
| Red | The Model B TLS endpoint rejects the Model A request when the client omits its certificate. |
| Green | A client with a different URI identity but a certificate signed by the same fixture CA reaches the peer identity policy and receives a fixed 403; it produces no authenticated-health event. |
| Positive | Model A receives the exact synthetic `/healthz` marker over TLS, and Model B records the fixed path with authenticated URI identity `urn:saf:model-peer:model-a`. |

The red check is a negative authentication test against a controlled mock
endpoint. It does not represent an observed vulnerable deployment. The green
check is based on runtime observations inside the two Linux Pod mount
namespaces, not on the `emptyDir` declarations alone. Memory accounting is
container cgroup accounting; it is not a per-model GPU utilization or GPU
memory measurement.

## Scope and adopter verification

This GPU-free fixture contains seven published assertions in each of the paired disposable Kind v1.36.1 runs:

1. Model A’s declared memory request/limit matches live accounting from A’s own cgroup.
2. Model B’s declared memory request/limit matches live accounting from B’s own cgroup.
3. Two distinct Pod mount namespaces expose separate bounded tmpfs mounts at `/dev/shm`; the same benign filename contains each Pod’s distinct fixed marker.
4. A fixed 1 MiB tmpfs write is charged to the writing Pod’s memory cgroup while the peer’s charge remains stable and its marker remains unchanged.
5. The mock Model B endpoint rejects the fixed request when Model A supplies no client certificate.
6. A second certificate signed by the same synthetic CA completes TLS but has a different URI identity; Model B denies it and emits no authenticated-health event.
7. The same fixed `/healthz` request succeeds with server certificate and hostname validation plus the exact allowed client identity; Model B records that URI identity.

These are fixture-only observations. The case uses separate mock Pods, a memory-backed `emptyDir`, cgroup counters, one case-owned ClusterIP Service, and temporary synthetic certificates. It does not run ModelMesh Serving, Triton, KServe, an inference server, model artifacts, a GPU, MIG/vGPU, or a production service mesh. The two Pods are not co-located models in a shared serving runtime. The case therefore demonstrates Pod-scoped tmpfs separation and CPU/memory cgroup accounting, not model-level memory isolation, shared-process isolation, GPU memory boundaries, GPU accounting, or model-serving behavior. A GPU scheduler or execution rate limit alone should not be described as per-model GPU-memory isolation.

The mTLS and peer-identity result is limited to one connection over the case-owned Service and one exact synthetic identity allowlist entry. It does not establish protection of external ingress, every internal call, service-mesh sidecars, every bypass path, certificate issuance/rotation/revocation, key custody, production identity mapping, or policy coverage. It does not validate traffic outside that one synthetic health request. There is no NetworkPolicy assertion and no attempt to access another Pod's mount or process memory.

### Adopter verification for a real serving deployment

Before making deployment-level claims, identify the exact runtime, version, topology, and accelerator stack. ModelMesh Serving’s `ServingRuntime.spec.multiModel` identifies runtimes intended for ModelMesh multi-model use and its runtime contract communicates loaded-model capacity/consumption; that is not itself proof that models have separate processes or GPU memory. Triton can load multiple models into a server and schedule their execution; inspect the documented controls actually enabled for the deployed backend and do not equate scheduling or model-load thresholds with per-model memory isolation.

Verify the configured boundary with supported observables for that runtime: determine whether each protected tenant/model has a separate process, Pod, or hardware-backed accelerator partition; confirm actual mounts and shared-memory ownership; and validate resource limits against live cgroup or vendor-supported accelerator telemetry at the granularity claimed. For accelerator isolation, check hardware, driver, device-plugin/runtime, and partition-mode support for the installed versions. Use MIG only on supported devices/configurations; NVIDIA documents time-slicing as sharing without memory/fault-domain isolation. Do not claim per-model GPU accounting from per-GPU metrics without validated model attribution. Keep verification to benign test workloads, synthetic markers, and documented observability; this case does not require reading a peer’s memory.

For transport protection, inventory every inference ingress and service-to-service hop, including sidecar and direct/bypass routes. Verify server identity/hostname validation and peer authentication at each applicable hop using approved synthetic identities and health requests. Confirm that policy actually covers the inventoried paths, and separately verify certificate issuance, rotation, revocation, trust roots, and key custody where those are part of the deployment requirement. A successful request on one path is evidence only for that path. The separate [SAF-K8S-0503-007 ingress TLS example](https://github.com/secure-agentic-framework/saf-k8s/blob/93a84a4a9cffd3c2a96f71f9d29196bf5bc1942a/tests/control-lab/verified/SAF-K8S-0503-007.json) demonstrates TLS termination on its own managed Traefik Gateway route; it is not joined to this mock inference route and does not replace this deployed all-hop verification.

The control rationale’s shared-memory leakage scenario is not validated by these separate-Pod fixtures. Any broader claim about ModelMesh/Triton behavior, shared-process leakage, resource starvation, GPU memory, or end-to-end TLS requires evidence from the actual supported runtime and deployment configuration. This case-level identity gate does not replace adopter verification of deployed certificate trust, peer-to-service identity policy, issuance/rotation/revocation, or all-path coverage.

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
