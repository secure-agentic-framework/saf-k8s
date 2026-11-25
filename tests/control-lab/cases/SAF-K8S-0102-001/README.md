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

## Verify backing media for live etcd

The supplementary test runs on a disposable ARM64 Debian guest with host
shares disabled. It starts a native Kind control plane on a plaintext ext4
image and checks that the exact synthetic API marker reaches both the live
etcd backend and the configured WAL, then finds the marker in the raw image.
A separate cluster repeats the native write on a LUKS2 filesystem. The
fixture joins effective etcd flags and the static Pod mount to the Kind node
bind mount and encrypted backing file. After the owned node is stopped and
the mapper is closed, the marker is absent from the raw encrypted image.
An unrelated key fails to unlock it. Reopening with the approved key and
restarting the same node restores the native API marker read.

The supplementary case ran twice on fresh plaintext and encrypted Kind
clusters and the guest was deleted. See [the paired guest receipt](live-etcd-luks.verified.json).
The key file is protected and separate from the encrypted image within the
test guest. For deployment, verify independent key custody and recovery for
the actual protected storage, provider and threat boundary as described above.

On a supported macOS ARM64 host with Lima, run the published fixture from this
case directory. The wrapper owns its own guest and cleans it up at the end.

```sh
fixture_dir="$(mktemp -d /tmp/saf-etcd-proof.XXXXXXXX)"
cp test-vm.yaml bootstrap.sh live-etcd-luks.sh run-owned-guest.sh "$fixture_dir/"
bash "$fixture_dir/run-owned-guest.sh" "$fixture_dir"
```

Review the guest bootstrap, image and binary pins before execution. The
wrapper records both run logs and the guest cleanup result in that directory.

- [Kubernetes v1.36 kubeadm configuration](https://v1-36.docs.kubernetes.io/docs/reference/config-api/kubeadm-config.v1beta4/)
- [etcd v3.6 storage options](https://etcd.io/docs/v3.6/op-guide/configuration/)
