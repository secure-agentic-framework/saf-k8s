# Active Qdrant storage on a LUKS2-backed volume

Run the active-volume demonstration in a disposable ARM64 Lima VM. It uses
the unprivileged Qdrant 1.20.2 ARM64 image and Kind v1.36.1. The VM has no
host filesystem mounts. The bootstrap installs guest Docker and the pinned
Kind and kubectl versions, with downloads checked against their recorded hashes.

From this directory on the host, choose an unused VM name and run:

```sh
vm=saf-qdrant-pv-lab
limactl start --name="$vm" --plain --mount-none --tty=false ./test-vm.yaml
limactl copy --recursive "$PWD" "$vm:/var/tmp/saf-qdrant-pv"
limactl shell "$vm" sudo -n env SAF_K8S_0102_001_DISPOSABLE_GUEST=I_OWN_THIS_DISPOSABLE_VM \
  bash /var/tmp/saf-qdrant-pv/bootstrap.sh
limactl shell "$vm" sudo -n env SAF_K8S_0701_003_DISPOSABLE_GUEST=I_OWN_THIS_DISPOSABLE_VM \
  SAF_K8S_0909_010_PV_ARM=arm-a bash /var/tmp/saf-qdrant-pv/guest-fixture.sh
limactl shell "$vm" sudo -n env SAF_K8S_0701_003_DISPOSABLE_GUEST=I_OWN_THIS_DISPOSABLE_VM \
  SAF_K8S_0909_010_PV_ARM=arm-b bash /var/tmp/saf-qdrant-pv/guest-fixture.sh
limactl stop "$vm"
limactl delete "$vm"
```

Each arm uses a new virtual disk, key and sequence of Kind clusters. The
Qdrant data path must mount the exact static PV under the guest's LUKS2
mapper. The write phase verifies the fixture point over trusted TLS, then
recreates the Qdrant Pod and reads the point again. After mapper close and
wrong-key denial, a fresh Kind cluster binds that same backing volume.
A new Qdrant Pod reads the exact point without writing it again.

At adoption, verify the active volume mapping for each governed workload,
effective provider encryption and key authority, snapshots and replicas,
and observed recovery after key rotation or an approved failure. The
separate local ext4 marker is the plaintext comparator. The Qdrant witness
uses exact volume mapping and post-reopen application readback.

[Qdrant security](https://qdrant.tech/documentation/security/) · [Lima copy](https://lima-vm.io/docs/reference/limactl_copy/)
