# SAF-K8S-0701-003 — Encryption at rest for persistent volumes

Run the Kubernetes API and admission checks from the control-lab directory.

```bash
python3 lab.py test SAF-K8S-0701-003 --docker-context desktop-linux
```

On Kubernetes 1.36.1, strict StorageClass validation rejected the catalog's original
`encryptionConfiguration` field. A scoped ValidatingAdmissionPolicy admitted a fixture
claim using the approved class and denied the same unapproved declaration that was
admitted before the policy. This checks which classes claims may declare. Verify the
encryption of the backing volume separately.

## Demonstrate a workload on encrypted storage

The supplementary fixture ran twice in independent kind clusters inside a dedicated
Linux VM with host shares disabled. An ordinary Pod wrote through a dynamically bound
PVC whose local-path backing was on a LUKS2 filesystem. The plaintext reference exposed
the exact Pod marker. A raw scan of the encrypted image found none of the fixture
markers. The wrong key was rejected, and the correct key reopened the Pod marker and
both local fixture files. [Guest receipt](guest-receipt.json).

1. On Apple Silicon, start the dedicated VM from [test-vm.yaml](test-vm.yaml) with
   `limactl start --name=saf-volume-encryption --plain --mount-none ./test-vm.yaml`.
2. In the guest, install `cryptsetup`, `e2fsprogs`, `openssl`, `docker.io`,
   `docker-cli`, and `python3` from the signed Debian repositories. Start the guest
   Docker daemon and install kind v0.32.0 and kubectl v1.36.1 after checking their SHA-256
   against the official distribution. The receipt records the ARM64 digests tested.
   [kind releases](https://github.com/kubernetes-sigs/kind/releases/tag/v0.32.0),
   [kubectl installation](https://kubernetes.io/docs/tasks/tools/install-kubectl-linux/).
3. Copy both guest scripts into the same directory inside the guest. From that
   directory, run `sudo env SAF_K8S_0701_003_DISPOSABLE_GUEST=I_OWN_THIS_DISPOSABLE_VM bash guest-fixture.sh`.
   The script creates a disposable image and kind cluster in the guest and verifies
   teardown. Remove the dedicated VM after the demonstration.

The test covers a single local LUKS2 implementation. Production StorageClass and
backend inventory, KMS custody and rotation, snapshots, and recovery remain on
`saf-lab-0701-003.2`.

[Kubernetes StorageClasses](https://v1-36.docs.kubernetes.io/docs/concepts/storage/storage-classes/) ·
[Kubernetes API resource encryption](https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/) ·
[Linux device-mapper encryption](https://docs.kernel.org/admin-guide/device-mapper/dm-crypt.html)
