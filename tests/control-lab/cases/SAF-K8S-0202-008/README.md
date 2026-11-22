# SAF-K8S-0202-008 — Runtime socket filesystem boundary

```sh
python3 lab.py test SAF-K8S-0202-008 --docker-context desktop-linux
```

Inspect the rootful containerd socket and every parent on a disposable
kind node. Record file type, mode and ownership. An unrelated numeric
UID/GID runs a pathname write-permission check without opening a connection.
The case never sends a request through the actual runtime socket.

A separate, case-owned Linux pathname socket serves a fixed local echo.
A permissive socket with a traversable directory permits the unrelated
test identity. Restricting the parent while leaving the mode unchanged
denies access. Restoring traversal and making only the socket restrictive
also denies it. The owner still completes the same echo. The Go helper
builds offline and removes its synthetic socket and copied executable.

The live sample covers rootful kind. Approved rootless runtimes have their
own identity and path. Effective groups, ACLs, provider controls and
workload mount restrictions need deployment evidence.

- [containerd operator permission guidance](https://github.com/containerd/containerd/blob/main/docs/security/OPERATOR_GUIDELINES.md#13-permissions-constraints)
- [containerd rootless guidance](https://github.com/containerd/containerd/blob/main/docs/rootless.md)
