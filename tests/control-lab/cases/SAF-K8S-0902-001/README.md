# SAF-K8S-0902-001 — Synthetic inference hardening

Run `python3 lab.py test SAF-K8S-0902-001 --docker-context desktop-linux`.
A nonroot Python fixture serves one inert model marker. A live probe verifies
the exact mounted bytes, immutable mount behavior, the read-only root, and
writable scratch. Disabling the root protection in a replacement Pod makes
the identical root filesystem write succeed. The workload egress policy allows
only the selected local peer on TCP 8080. Both listeners work before policy,
and a separate Pod still reaches the denied destination afterward.

The original checks cover one local Kind CNI and a synthetic inference service.
Production model backends, approved egress inventory, scanning, and patch
cadence still need separate evidence.

- [Kubernetes Security Context](https://v1-36.docs.kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [Kubernetes NetworkPolicy](https://v1-36.docs.kubernetes.io/docs/concepts/services-networking/network-policies/)

The liveness check runs a separate restricted Pod using the same pinned Python
image. Its unprivileged process gets a 1 MiB scratch volume. A fixed marker makes
only the liveness route return HTTP 503. The case requires the matching kubelet
liveness failure Event, exactly one container restart under the original Pod UID,
a new container ID, and recovery to Ready with HTTP 200 and the marker cleared.
Adopters should verify the deployed server's liveness contract and safe restart
conditions under their actual serving configuration.

## Pinned CPU serving supplement

The candidate keeps all eight existing fixture and liveness checks, then adds
three checks using the official llama.cpp b9519 CPU server with the tiny pinned
Stories model also used by SAF-K8S-0903-004. The runner fetches the model over
HTTPS, checks its fixed size and SHA-256, and builds the derived image with
network disabled during image build. It loads the existing `llama_runtime.py`
and `Dockerfile.llama` from the adjacent SAF-K8S-0903-004 case only after
checking their pinned hashes; those files are not duplicated in the 0902-001
case tree.

A nonroot init container (UID/GID 65534) copies the already pinned model from
the derived image to a 96 MiB disk-backed `emptyDir`, then sets file mode 0444.
The init process is explicitly UID/GID 65534 and the Pod `fsGroup` is 65534.
Kubernetes v1.36.1's `emptyDir` setup applies `fsGroup` volume ownership before
containers start; the case also observes the completed init exit and the
resulting model file owner/group/mode. The running server mounts the artifact read-only and
loads the model from that path; its root filesystem is read-only, service
account token automount is off, capabilities are dropped, privilege escalation
is disabled, and seccomp is `RuntimeDefault`. A named `verify` container in the
same Pod checks the artifact bytes and mount flags, then sends one fixed
request to `localhost`; Kubernetes documents shared Pod loopback networking.
The case records the `verify` container's actual Running/Ready status; without
a readiness probe Kubernetes assumes a running container is ready. It also
records the init container's successful exit. The probe companion is SHA-256 checked before
creation and after reading it back from its immutable ConfigMap.

The case reads `/proc/self/mountinfo` inside the server container to observe
that `/` and `/artifact` are mounted read-only. It checks the token path with a
read-only existence query; it makes no write attempt. Named raw evidence keeps
the Pod API document, mountinfo, token-path result, model digest, image IDs,
companion pins, and bounded inference receipt. Check details contain only
normalized booleans and fixed counts.

This supplement shows that the pinned CPU server can load and serve this one
fixed model from a read-only artifact mount under the case's restricted
container posture. It does not validate production serving images, dependency
scanning/advisory response/patch cadence, egress inventory, availability
under real model workloads, GPU/CUDA behavior, or other frameworks.

Kubernetes sources for the added fixture: [v1.36 Pod security context and
`fsGroup`](https://v1-36.docs.kubernetes.io/docs/tasks/configure-pod-container/security-context/),
[v1.36 `emptyDir`](https://v1-36.docs.kubernetes.io/docs/concepts/storage/volumes/),
[same-Pod localhost communication](https://v1-36.docs.kubernetes.io/docs/concepts/workloads/pods/).
The exact v1.36.1 kubelet source invokes volume ownership handling for `emptyDir`
([plugin](https://github.com/kubernetes/kubernetes/blob/v1.36.1/pkg/volume/emptydir/empty_dir.go#L257-L258),
[Linux group/mode update](https://github.com/kubernetes/kubernetes/blob/v1.36.1/pkg/volume/volume_linux.go#L135-L165)).
Kubernetes documents that a container without a readiness probe is considered
ready when running ([Pod debugging](https://v1-36.docs.kubernetes.io/docs/tasks/debug/debug-application/debug-running-pod/)).
The pinned model runtime references the [official b9519 CPU
Dockerfile](https://github.com/ggml-org/llama.cpp/blob/b9519/.devops/cpu.Dockerfile)
and [server API](https://github.com/ggml-org/llama.cpp/blob/b9519/tools/server/README.md).
