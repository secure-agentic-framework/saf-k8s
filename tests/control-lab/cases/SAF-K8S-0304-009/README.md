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

The case covers application-layer encryption of actual bytes on temporary
storage, file access in this Pod and namespaced API authorization. A real
training pipeline needs separately verified storage-provider encryption,
persistent key management, resume across process/node boundaries, and
checkpoint lifecycle controls. The framework retains
`verified/SAF-K8S-0304-009.json`.

- [Kubernetes v1.36 emptyDir volumes](https://v1-36.docs.kubernetes.io/docs/concepts/storage/volumes/#emptydir)
- [Kubernetes v1.36 RBAC authorization](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/)
- [Go standard-library AES-GCM interface](https://pkg.go.dev/crypto/cipher#NewGCM)
