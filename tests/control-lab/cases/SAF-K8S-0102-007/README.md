# SAF-K8S-0102-007 — etcd backup artifact encryption

Requires the official `age` and `age-keygen` command line tools.

```sh
python3 lab.py test SAF-K8S-0102-007
```

The case uses a fresh Kubernetes v1.36.1 kind cluster, etcd v3.6.8, and one
synthetic ConfigMap marker. It takes the native snapshot through the isolated
case-owned kind etcd method used by SAF-K8S-0102-008, then age-encrypts the
snapshot artifact into a mode-0700 temporary staging directory. Only synthetic
fixture bytes are inspected, and test output never includes backup bytes or key
material.

The red observation confirms that the source snapshot is a readable native
etcd artifact and contains the synthetic marker before export encryption. The
green observation confirms that the encrypted artifact is neither a native
snapshot nor marker-readable. Two fresh age identities are generated: a
synthetic source-key proxy and a distinct backup key. The source proxy is
rejected, while the backup identity decrypts to bytes with the exact source
SHA-256 digest and the same native etcd snapshot revision. A final red check
modifies the encrypted artifact and confirms authenticated decryption rejects
it.

This validates an artifact encryption layer and key separation in a local test;
the synthetic source key is only a wrong-key comparison. It does not claim that
kind's live etcd volume is encrypted or demonstrate equivalent live-volume
protections. Plaintext exists briefly during snapshot creation and encryption
inside the private temporary directory. Production controls must protect that
creation and staging path, encrypt persisted backup objects with a separately
managed backup key, protect key custody and transfer, and verify the actual
storage provider configuration. Encryption alone does not prove backup access
restriction, storage-provider encryption-at-rest, integrity manifests,
signature provenance, or restore readiness.

## Control review notes

| Obligation | Case evidence | Boundary |
| --- | --- | --- |
| Encrypt snapshots and archives | Encrypted artifact is not a native etcd snapshot and does not expose the fixture marker | Local age encryption does not inspect a production backup repository's at-rest settings |
| Separate backup key from the source encryption key | Snapshot encrypts to a newly generated backup recipient; a distinct source-proxy identity fails decryption | The source proxy is synthetic; no live-volume key or KMS is accessed |
| Integrity assurance | age authenticated decryption rejects a modified ciphertext; exact decrypted digest is preserved | SAF-K8S-0102-008 is the catalog control for backup integrity evidence and restore assurance |
| Live etcd storage encryption | Not tested | Requires separate evidence under SAF-K8S-0102-001 and the real infrastructure/KMS configuration |

The original catalog entry cited SAF-K8S-0102-003, an identifier absent from
the catalog revision under review. SAF-K8S-0102-008 covers backup integrity
and restore assurance. The revised catalog points to that control.

## Versioned and primary references

- [Kubernetes v1.36: operating etcd clusters](https://v1-36.docs.kubernetes.io/docs/tasks/administer-cluster/configure-upgrade-etcd/)
- [etcd v3.6: disaster recovery and snapshots](https://etcd.io/docs/v3.6/op-guide/recovery/)
- [age v1 file format specification](https://age-encryption.org/v1)
- [age official command documentation](https://github.com/FiloSottile/age/tree/v1.3.1/doc)
- SAF-K8S-0102-001 governs etcd storage-layer disk encryption; SAF-K8S-0102-008 governs etcd backup integrity verification and restore assurance. The latter's local executable case is at `../SAF-K8S-0102-008/`.
