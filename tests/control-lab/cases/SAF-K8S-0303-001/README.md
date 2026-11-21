# SAF-K8S-0303-001 — Seccomp profile enforcement

The case switches a test namespace from PSA Baseline to Restricted at v1.36.
It submits the same Pod without a seccomp setting on each side of the change.
Restricted rejects omitted and explicit Unconfined settings. A server dry-run
against the ephemeral-container subresource checks both denial cases and
accepts RuntimeDefault.

The test also runs BusyBox app and init containers. Each reports filter mode 2
with a Pod-level RuntimeDefault inherited by both containers or with an explicit
per-container RuntimeDefault. These observations verify effective filter mode
for the pinned kind node and runtime.

The Localhost comparison runs the same harmless uname syscall in two identical
pinned Python fixtures. RuntimeDefault permits the call; a read-only Localhost
test profile configured on the disposable node returns EPERM. The fixture
supports the recorded Linux aarch64 and x86_64 syscall numbers. The test policy
allows calls by default to isolate the comparison. A production profile needs a
workload-specific allowlist, review, and lifecycle controls.

The control's profile governance, exception process, production workloads, and
other runtime and provider configurations remain separate evidence obligations.

- [Kubernetes v1.36 seccomp tutorial](https://v1-36.docs.kubernetes.io/docs/tutorials/security/seccomp/)
- [Kubernetes v1.36 Pod Security Standards](https://v1-36.docs.kubernetes.io/docs/concepts/security/pod-security-standards/)
