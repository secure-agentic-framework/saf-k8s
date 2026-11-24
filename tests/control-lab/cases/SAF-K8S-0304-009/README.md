# SAF-K8S-0304-009 — Temporary checkpoint protection

```sh
python3 lab.py test SAF-K8S-0304-009 --docker-context desktop-linux
```

The case requires local Go and a Linux arm64 or amd64 kind node. It builds a
standard-library Go binary for that architecture, loads a case-specific scratch
image into the disposable cluster and removes the local image tag after use.

A baseline writes an inert marker to a disk-backed `emptyDir`. The protected
Pod instead writes an AES-256-GCM envelope with a fresh nonce under a
process-local key and file mode `0600`. It accepts the original checkpoint and
rejects an altered ciphertext from that volume before reuse. A second container
with a different UID cannot open the file for reading or writing.

A separate API check verifies the same encrypted record is readable and
patchable through its exact named ConfigMap only by the intended synthetic
ServiceAccount. A second identity and unrelated resource requests receive
RBAC denials. The Pod fixtures disable token automount. The checks use
synthetic identities and retain no credentials or production data.

The resume probe stores a separate synthetic key in a memory-backed
`emptyDir` with mode `0600` and keeps the encrypted checkpoint on disk.
Each read starts a fresh process in the same Pod. The probe resumes from the
authorized record and checks distinct denials for altered ciphertext, the
wrong run or step, an expired record and a future timestamp. It removes the
owned files and key and checks that they are absent. The framework retains
`verified/SAF-K8S-0304-009.json`.

## Adopter checks

- Identify where the checkpoint is written, replicated, backed up and deleted.
  Record the configured encryption mechanism at each location. Verify the
  authorized workload can resume and that an unrelated workload identity is
  denied both checkpoint and key access.
- In a representative environment, exercise the same restart, reschedule
  and restore paths your training workload relies on. Keep an evidence
  record of the expected training run and step, approved freshness window,
  result and reason for each denied restore.
- Inspect key custody and access logs. Exercise the relevant key rotation,
  revocation and restore cases on synthetic data. Verify retention and
  deletion against the actual storage provider, including copies and
  backups. The fixture key is scoped to one disposable Pod.

- [Kubernetes v1.36 emptyDir volumes](https://v1-36.docs.kubernetes.io/docs/concepts/storage/volumes/#emptydir)
- [Kubernetes v1.36 RBAC authorization](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/)
- [Go standard-library AES-GCM interface](https://pkg.go.dev/crypto/cipher#NewGCM)
