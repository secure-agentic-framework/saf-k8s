# SAF-K8S-0901-003 — Checkpoint security

Run with `python3 tests/control-lab/lab.py test SAF-K8S-0901-003` from SAF-K8S.
The case prepares one disposable Kubernetes v1.36.1 Kind cluster with a temporary
Secretbox encryption key. It inspects only the exact backend storage keys for the
synthetic checkpoint Secret and a plaintext ConfigMap comparator, and emits
only booleans from those reads.

One fixture workload uses its named service account to read the trial checkpoint
and the separate approved digest manifest. The same validation path refuses a
changed checkpoint before restore. A separate unbound workload receives HTTP
403 for read and write. An independently authorized observer verifies the
restored checkpoint bytes and optimizer metadata. The runtime output retains
only scoped assertions and fixture hashes in `checkpoint-observations.raw.json`.

The untrusted workload also attempts a metadata-only patch against the exact
checkpoint input Secret, without submitting checkpoint or optimizer bytes. The
case requires HTTP 403 and independently reads the Secret before and after to
compare its UID, resourceVersion, and checkpoint and optimizer digests. This
tests write denial on the protected source object separately from the existing
write denial on the restore destination.

This demonstrates the small API-stored fixture. Actual training checkpoints,
filesystem or object-store encryption, production identities, KMS and key
custody, and distributed state recovery require separate evidence.

- [Kubernetes v1.36 encryption at rest](https://v1-36.docs.kubernetes.io/docs/tasks/administer-cluster/encrypt-data/)
- [Kubernetes v1.36 RBAC](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/)
