# SAF-K8S-0203-011 — Verified fixture roots and writable state

```sh
python3 lab.py test SAF-K8S-0203-011 --docker-context desktop-linux
```

A restricted Kind Job uses QEMU to boot four isolated Linux guests with owned
disks. The writable comparison root accepts a public marker. Before each
protected boot, OpenSSL verifies the Ed25519 signature and the fixture checks
the release label and current SHA-256 of the whole root image. The signature
check rejects changed metadata and the digest check rejects changed image
bytes. The first approved root rejects the marker and permits separate state.
The approved replacement retains and writes that state. The selected prior
release then boots with the update marker still present. Both root images
match their original signed digests afterwards.

The lab key and trust anchor are generated within each run. The retained
evidence includes only fixture image identities, release labels, and guest
observations. The lab uses Debian ARM64 QEMU and an ext4 root mounted
read-only with a read-only backing disk.

## Verify deployment applicability and evidence

1. Inventory exact deployed node OS builds, provider ownership, relevant pools,
   documented protected roots and allowed write paths. Bind each root to the
   approved release, signer or provider evidence. Record exceptions and scope.
2. For a self-managed Linux node, collect read-only `findmnt -no SOURCE,FSTYPE,OPTIONS /`
   and mounts for permitted writable paths. For opaque nodes, retain the
   provider's precise image and mechanism evidence. An ordinary Pod root
   setting applies to that container and provides its own separate evidence.
3. In a disposable staging node, challenge a harmless owned root path and
   exercise an approved writable path. Use an authorized, supported updater
   to transition from an approved image to another version, then test the
   supported recovery path. Verify booted image identity, denied root write,
   retained state, runtime readiness and recovery behaviour after each step.
   Check that a locally modified test package fails your release verifier.
4. Where the chosen design promises verified boot or dm-verity, separately
   validate the trusted root hash, boot chain and actual integrity status.
   Record boot policy and trusted measurements from that OS or provider.
   Track unexpected image and mount changes and lifecycle exceptions with
   accountable owners and evidence dates.

[OpenSSL signature operations](https://docs.openssl.org/3.5/man1/openssl-pkeyutl/) ·
[Linux dm-verity](https://docs.kernel.org/6.12/admin-guide/device-mapper/verity.html) ·
[Kubernetes v1.36 security context](https://v1-36.docs.kubernetes.io/docs/tasks/configure-pod-container/security-context/)
