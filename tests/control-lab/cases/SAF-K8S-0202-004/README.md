# SAF-K8S-0202-004 — Runtime socket mount prevention

## Case scope

This case uses the namespace-scoped Kubernetes Pod Security Admission (PSA)
Baseline profile as the defensive control. Baseline disallows `hostPath`
volumes, which blocks direct runtime socket mounts and mounts of a parent
directory that could expose a socket. It is broader than socket-only blocking:
applications that legitimately need any hostPath will also be denied and need
a separately reviewed design.

`fixtures.yaml` contains only inert, deliberately nonexistent example paths.
Each negative challenge is sent with `--dry-run=server` before and after
enforcement. The violating Pod objects are never persisted, scheduled, or run.
No real runtime socket is mounted, inspected, contacted, or used. The positive
control admits and starts a restricted BusyBox Pod with no hostPath.

## CI/CD builder proof boundary

The case does not include or test a CI/CD builder. A separate builder review
must establish from its actual configuration and execution environment that
build steps cannot reach a privileged host daemon or socket and that the
builder runs rootless and/or daemonless as claimed. Useful evidence would
include the builder identity and process configuration, socket/device and
host-path mappings, daemon endpoint configuration, and a benign build result
under those restrictions. Admission evidence for Kubernetes Pods does not
prove those pipeline properties.

## Verification status

Prepared for the local lab runner using its pinned Kubernetes 1.36.1 kind node
image. No cluster run or catalog review was performed while preparing this case;
PSA enforcement, server dry-run responses, and readiness remain unverified.
