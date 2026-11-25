# SAF-K8S-0102-007 — etcd backup artifact encryption

Requires the official `age` and `age-keygen` command line tools.

```sh
python3 lab.py test SAF-K8S-0102-007
```

The case uses a fresh Kubernetes v1.36.1 kind cluster, etcd v3.6.8, and one
synthetic ConfigMap marker. It first shows plaintext with a test snapshot.
Then it captures a new native snapshot on private, bounded `noswap` tmpfs and
streams it to age. The persistent staging directory receives ciphertext. The
receipt records only the comparison results.

The red observation confirms that the source snapshot is a readable native
etcd artifact and contains the synthetic marker before export encryption. The
green observation confirms that the encrypted artifact is neither a native
snapshot nor marker-readable. Two fresh age identities are generated: a
synthetic source-key proxy and a distinct backup key. The source proxy is
rejected, while the backup identity decrypts to bytes with the exact source
SHA-256 digest and the same native etcd snapshot revision. A final red check
modifies the encrypted artifact and confirms authenticated decryption rejects
it.

The synthetic source-key proxy demonstrates rejection by the backup key
boundary. Collect actual volume keys, storage, custody and transfer policy
through the adopter procedure. SAF-K8S-0102-008 covers separate backup
integrity and restore assurance.

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

## Retention and recovery comparison

The red comparison deliberately writes a readable synthetic snapshot, verifies
that it is a native etcd artifact, and removes it. The protected comparison
mounts a private 16 MiB tmpfs with `noswap` inside only the case-owned Kind
node, then verifies the effective filesystem and option. The pinned etcd
process supplies the native snapshot and inspection tools. Native
`etcdctl` writes there and the case streams those bytes directly into age,
without creating a host plaintext file during staging. The two possible
volatile snapshot paths and the fixture mount are removed before recovery.
Only ciphertext is moved to the separate retention directory. The approved backup identity recovers
the exact expected digest and native revision in an isolated private directory.

Validate separate staging encryption and swap/hibernation policy for the actual
platform. Collect separate host-paging, physical media erasure, and service storage
encryption evidence where applicable.
[Linux tmpfs mount documentation](https://docs.kernel.org/filesystems/tmpfs.html).

## Adoption evidence guide

For each real provider, tier, and backup path, retain sanitized evidence tied to the cluster, job, destination, and object/version:

1. **Provider policy:** Record the storage service's encryption-at-rest setting, algorithm/service mode, key identifier/version, scope (staging, replicas, retention and offline copies), and effective policy/configuration. Confirm a representative object is covered; a successful local `age` command or provider default is not enough.
2. **Transport:** Verify TLS or the approved encrypted transfer mechanism from snapshot creation through staging, upload, replication, and restore download. Retain sanitized endpoint/policy/job evidence and any required certificate or peer validation result. At-rest encryption does not establish in-transit protection.
3. **Offline custody:** Document how offline media/objects and the corresponding backup key are separately controlled, stored, inventoried, and recovered. Record custody handoffs, access logs, key rotation/revocation, and break-glass procedure tests without exporting keys or cluster data.
4. **Privilege separation:** Compare principals and policies for live etcd volume keys, backup encryption keys, backup object read/write/delete, and restore operations. Demonstrate that a live-volume administrator cannot implicitly decrypt retained backups and that routine backup writers cannot retrieve key material; inspect scoped grants and audit trails.
5. **Acceptance evidence:** Complete an authorized recovery test from each materially distinct destination/tier using the approved identity. Preserve job/object version, provider key ID/version, policy snapshot, transfer result, integrity check, restored revision or other non-sensitive verifier, recovery approval, cleanup, and exception disposition. Do not include plaintext resource data or key material.
