# SAF-K8S-0302-001 — Pod and container security context enforcement

## Reference scope

The pinned catalog entry is `SAF-K8S-0302-001` at source commit
`133a8698a45e2b335b51728bf4c62f7bda98d15f`:
[control statement](https://github.com/secure-agentic-framework/saf-k8s/blob/133a8698a45e2b335b51728bf4c62f7bda98d15f/markdown/controls/SAF-K8S-0302-001.md).
Its local catalog title is “Pod and container security context enforcement.”
The D03 3.2 knowledge area identifies `runAsNonRoot`, `runAsUser`,
`readOnlyRootFilesystem`, and `allowPrivilegeEscalation` as container security
context settings. This reference requires each field explicitly on every app,
init, and separately added ephemeral container in the labeled synthetic namespace.

The policy only matches Pods in namespace `saf-0302-001`, selected by the
`saf-k8s.example/enforce-container-context=true` label. There is no exception:
the policy is small and scoped to this synthetic namespace, and all four controls
are applicable to the sample workload. It does not attempt to define workload
specific production exceptions.

## Probes and limits

`case.py` is a runnable lab case, but this request authorizes static checks only;
no cluster run or evidence result is claimed here. Noncompliant Pod CREATE
shapes and ephemeral container UPDATEs use `--dry-run=server`; no failing Pod or
debug container is persisted. The allowed BusyBox reference Pod has an init
container and app container, uses UID 65534, checks the root mount's `ro` flag,
confirms a harmless root-level temp-file write is denied, and confirms `/tmp`
remains writable. No privilege escalation or host access is attempted.

The policy covers the ephemeralcontainers subresource because Kubernetes adds
debug containers separately after Pod creation. This avoids leaving that path
outside the stated per-container enforcement scope.
