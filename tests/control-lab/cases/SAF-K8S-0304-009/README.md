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

## Promotion comparison

The retained checkpoint is written to a case-owned promotion destination only
after the fresh process applies the same authenticated envelope, run, step,
and freshness gate used for restore. An allowed promotion preserves the exact
verified ciphertext, which is accepted on reinspection. Tampered, wrong-run,
wrong-step, stale and future envelopes surface their expected rejection and
leave neither a destination nor a staging file. The destination is a local
reference fixture. Exercise the adopter's actual promotion path with the same
allowed and refused selections and ensure only the approved storage identity
can publish it.

## Cross-Pod ciphertext handoff

The current public receipt passed all 19 checks, including this cross-Pod extension with a separate producer, valid consumer, altered-input consumer, and wrong-key consumer. A producer Pod reads a per-case 32-byte key from a mounted,
case-owned Secret and writes an AES-GCM envelope directly to a pre-created,
named ConfigMap over verified Kubernetes API TLS. Its ServiceAccount can patch
only that ConfigMap. The Go probe emits only a boolean result; key bytes and
envelope bytes never appear in process output or command logs. The harness
briefly reads the encrypted object in memory to create the altered-ciphertext
case, using a mode-0600 private file for that update. A distinct consumer Pod
mounts the exact named ciphertext and key Secret, then runs the existing Go
authenticated run, step, and freshness validation and exact-ciphertext
promotion path.

The matched checks reject an altered ciphertext and a wrong-key outsider in
separate consumer Pods before any promotion destination or staging file
exists. They accept an exact producer envelope and verify successful promotion
while comparing promoted bytes with the original encrypted input. Synthetic RBAC checks allow the intended consumer identity to
get only the named handoff ConfigMap and key Secret; they deny collection,
unrelated-object, and outsider reads. Producer API TLS and its named patch
permission are exercised by the producer Pod. Consumer API permissions are
checked through Kubernetes authorization impersonation; the mounted objects
are delivered by the kubelet. The consumer Pods disable token automount. This
is a bounded fixture of scoped identity policy and cross-Pod ciphertext
handling, not proof that a production Pod made the API read or that a provider
KMS, encryption-at-rest layer, external custody, rotation, backup, or deletion
path is correctly configured.

The key bytes are generated in memory and written to a mode-0600 temporary
manifest only for Secret creation; that file is removed immediately. The
altered ciphertext manifest is similarly temporary. The original ciphertext
is read in memory by the harness but never printed, placed in a command
payload, or copied into evidence. Evidence records only booleans and result
names. The run verifies the owned temporary API key objects are deleted after the supplied Pods finish.

For adoption, capture the actual producer and consumer service accounts,
named API permissions, key-provider identity and custody policy, key version,
rotation/revocation result, ciphertext object identifiers, and audit events.
Exercise an authorized restart/reschedule/restore with the same expected run,
step, and freshness bounds, then verify an unrelated identity cannot retrieve
either ciphertext or key. Keep provider and workload evidence separate from
this synthetic reference result.
