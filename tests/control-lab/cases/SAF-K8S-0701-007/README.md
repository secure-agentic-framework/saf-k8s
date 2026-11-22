# SAF-K8S-0701-007 — Hardening storage workloads

```bash
python3 lab.py test SAF-K8S-0701-007 --docker-context desktop-linux
```

On Kubernetes 1.36.1, the same synthetic privileged and hostPath Pod declarations
were accepted by server-side dry-run before Restricted Pod Security Admission and
denied for the expected reasons afterward. The test separately schedules a nonroot
writer and a nonroot reader against a dynamically bound local-path PVC. The reader
retrieves the writer's marker, sees a read-only mount and fails to write to it.

Dedicated storage-driver namespaces and exceptions, actual high-performance
storage drivers, host security profiles, and risk reviews require deployment
evidence. [Kubernetes Pod Security Standards](https://v1-36.docs.kubernetes.io/docs/concepts/security/pod-security-standards/).
