# SAF-K8S-0301-003 — Stage Pod Security Admission before enforcing it

```sh
python3 lab.py test SAF-K8S-0301-003 --docker-context desktop-linux
```

Kubernetes 1.36.1 discovery and a direct lookup confirm removal of
PodSecurityPolicy. A harmless Pod that omits two Restricted settings is sent
only as a server dry-run. Baseline accepts it. Restricted audit and warn
still accept that same request, while returning the expected warning and
emitting the Restricted annotation on the scoped metadata-level API audit
event. When enforcement is enabled, Kubernetes refuses the identical dry-run
for the expected policy reason. A separate compliant Pod is admitted and
reaches Ready.

The test covers a namespace migration sequence on a modern API server.
Inventory legacy PSP rules, handle defaulting and custom policy gaps, and
verify administrator ownership, system namespace coverage and the phased
upgrade on the target deployment.

[Kubernetes migration from PSP](https://v1-36.docs.kubernetes.io/docs/tasks/configure-pod-container/migrate-from-psp/) ·
[Pod Security Admission](https://v1-36.docs.kubernetes.io/docs/concepts/security/pod-security-admission/) ·
[Kubernetes API auditing](https://v1-36.docs.kubernetes.io/docs/tasks/debug/debug-cluster/audit/)
