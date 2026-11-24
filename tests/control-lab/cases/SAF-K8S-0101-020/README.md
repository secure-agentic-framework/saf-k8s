# SAF-K8S-0101-020 — API server profiling and debug exposure disablement

## Coverage and comparison

The case creates two separate disposable kind clusters from the node image
pinned in `lab.py`: one with explicit `--profiling=true` and one with explicit
`--profiling=false`. In each cluster it reads only the API-server Pod's
effective command vector and requires exactly one matching profiling flag. It
also checks the separate `--debug-socket-path` argument by name. An absent or
explicitly empty value passes; a nonempty value fails. This inspects the
configured argument only. It never stats, opens, or connects to a socket.

The case obtains the selected cluster endpoint, CA, and client identity from
that profile's runner-created kubeconfig. It refuses an endpoint unless it is
HTTPS on an IP loopback address and uses that kubeconfig's mTLS identity for
exactly two GET paths:

| Profile | `GET /debug/pprof/` | `GET /livez` |
| --- | --- | --- |
| `--profiling=true` | HTTP 200 expected (red observation) | HTTP 200 expected (positive) |
| `--profiling=false` | HTTP 404 expected (green observation) | HTTP 200 expected (positive) |

Both response bodies are drained and discarded. In particular, the pprof index
is never printed or retained. No profile, heap, trace, command-line, symbol,
expensive diagnostic, or other debug handler is requested. No API address from
outside the runner-owned kubeconfig is accepted. Both case-owned clusters are
deleted, including after partial creation.

## Source/configuration checks and limits

The case checks `--debug-socket-path` independently from `--profiling`; turning
profiling off does not count as evidence that a separately configured socket is
absent. The check is limited to the effective kube-apiserver Pod command. It
does not inspect filesystem paths, mounted files, listeners, custom binaries,
or undocumented socket configuration mechanisms, and it performs no socket
access.

This is a narrow check of the standard pprof index registration behavior, not a
complete inventory of API-server debugging surfaces. It does not inspect or
request `/debug/flags/v`, other `/debug/` handlers, metrics, logs, health
subpaths, or any extension or proxy that could expose diagnostics. It does not
demonstrate that every individual pprof handler is unreachable; no such handler
is called for safety. The exact v1.36.1 source shows that the HTTP profiling switch also governs
HTTP debug-flag registration and the reset-capable metrics variants. Disabling
profiling leaves ordinary metrics when metrics are enabled. The Unix debug
socket and the control-plane logs handler have separate configuration paths.
The tagged sources support these registration claims. The live replay probes
only the allowlisted index and health paths.

The pinned control also covers production clusters, sensitive/shared or
production-path non-production clusters, managed Kubernetes customer-exposed
settings, and compensating controls where provider settings cannot be changed.
This kind-only test establishes none of those deployment-specific conditions
or compensating controls. It does not check API-server provisioning drift,
external load balancers or proxies, other Kubernetes versions, or hosted
control-plane behavior.

## Version and verification status

- Catalog source: `SAF-K8S-0101-020` at framework commit
  `133a8698a45e2b335b51728bf4c62f7bda98d15f`,
  `markdown/controls/SAF-K8S-0101-020.md`.
- Profile image: `kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5`.
- The case configures and checks kube-apiserver flags for Kubernetes v1.36.1
  only. It makes no claim for other versions or managed API servers.
- The live v1.36.1 replay observed HTTP 200 with profiling enabled, HTTP 404 with profiling disabled, and successful health checks in both profiles. Both clusters were deleted.

## References

- [Kubernetes v1.36 kube-apiserver command reference](https://v1-36.docs.kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/)

## Scoped authorization comparison

The case uses Kubernetes impersonation only on the disposable, TLS-verified
loopback endpoints. The fixed fixture identity receives HTTP 403 with the
index enabled and no grant. An exact `get` rule permits only the index, which
then returns HTTP 200. Native SubjectAccessReview confirms denial for the
fixture identity's other tested diagnostic permissions without executing the
corresponding handlers. When profiling is disabled, the same index grant
still yields HTTP 404. Managed-provider settings, external restrictions,
and actual organizational authorization require deployment evidence.

- [Kubernetes v1.36.1 generic API registration](https://github.com/kubernetes/kubernetes/blob/v1.36.1/staging/src/k8s.io/apiserver/pkg/server/config.go#L1120-L1148)
- [Kubernetes v1.36.1 control-plane logs registration](https://github.com/kubernetes/kubernetes/blob/v1.36.1/pkg/controlplane/apiserver/server.go#L96-L104)
- [Kubernetes v1.36 SubjectAccessReview](https://v1-36.docs.kubernetes.io/docs/reference/kubernetes-api/authorization-resources/subject-access-review-v1/)
