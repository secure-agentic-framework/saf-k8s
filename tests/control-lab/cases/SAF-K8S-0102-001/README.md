# SAF-K8S-0102-001 Offline etcd storage encryption

Kind runs an isolated etcd member containing one public marker. Its snapshot is written to an offline ext4 image, encrypted into LUKS by QEMU, and restored using a passphrase held on a different, memory-only mount. The test compares the complete raw image after restoration and checks that the plain image exposes the marker while the encrypted image does not.

The first run builds the pinned Alpine tool image and loads it into Kind. It uses no host block devices, storage accounts or real etcd data. Encryption for deployed backing volumes, provider-managed backups and external key custody needs separate deployment evidence.
