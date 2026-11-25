# SAF-K8S-0102-001 Offline etcd storage encryption

Kind runs an isolated etcd member containing one public marker. Its snapshot is written to an offline ext4 image, encrypted into LUKS by QEMU, and restored using a passphrase held on a different, memory-only mount. The test compares the complete raw image after restoration and checks that the plain image exposes the marker while the encrypted image does not.

The first run builds the pinned Alpine tool image and loads it into Kind. It uses no host block devices, storage accounts or real etcd data. Encryption for deployed backing volumes, provider-managed backups and external key custody needs separate deployment evidence.

## Adopter verification

1. Record the etcd release, member and infrastructure inventory. Resolve
   effective `data-dir` and `wal-dir` through each mount to the associated
   device, block volume or managed service. Include applicable snapshots and
   infrastructure images and record each evidence source.
2. Verify effective storage encryption, covered device or snapshot scope,
   and active key identifier/version for each row. For managed etcd, record
   provider and customer responsibilities and release-specific service evidence.
3. Record who can administer the media and who can authorize unlock or key
   use. Inspect effective grants, approval and audit evidence, and the
   rotation, revocation and recovery procedures. Keep key material outside the
   assessment artifacts.
4. Run an approved off-line recovery exercise with representative material.
   Check authorized recovery, refusal with an unrelated key where supported,
   data integrity, and coverage of retained snapshots. Record any excluded
   path or applicable provider evidence gap with an owner and expiry.

Assess API-object encryption and separately retained backups through
[SAF-K8S-0101-003](../SAF-K8S-0101-003/README.md) and
[SAF-K8S-0102-007](../SAF-K8S-0102-007/README.md). The local QEMU comparison
covers an offline image. Record the actual live path-to-device join separately.
