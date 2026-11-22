# Kubernetes v1.37 bind-mount flags on the CRI-O candidate

The [runtime receipt](runtime.json) records two independently created Pods on
one disposable, mount-free Debian 13.6 ARM64 VM. Kubernetes v1.37.0 exposed
`VolumeBindMountOptions` as an alpha feature. The API server and kubelet gates
were enabled, the CRI reported `mount_options: true`, and the kubelet declared
`VolumeBindMountOptions` on the Node.

The nonroot fixture used one `emptyDir` in both containers. The guarded
container reported `rw,nosuid,nodev,noexec,relatime` on `/work`. Direct
execution of its benign script failed with permission denied and exit 126.
The reference reported `rw,relatime` and executed the same file successfully.
Both containers wrote an ordinary record and read the other container's record.
The fixture reports these observations in its Pod termination status. Both
runs deleted their namespace.

The runtime is an unreleased build from [CRI-O PR #10397 at the pinned source
commit](https://github.com/cri-o/cri-o/commit/cab6acc7cd24156461b54f94a64f2f33f9be34dc).
The candidate reports `1.38.0` at runtime. The source archive and binary hashes
are retained in [build.json](build.json). The [containerd 2.3.4
receipt](v1.37-containerd-2.3.4.json) captures the separate
unsupported arm, where kubelet rejected the configured Pod with
`PodFeatureUnsupported`. Released CRI-O support, other volume and runtime
handlers, and other platforms require independent evidence. The fixture
checks the effective `nodev` and `nosuid` flags. It exercises behavior only
for `noexec`.

## Reproduce in a disposable guest

1. Build the verified pinned source with [Dockerfile](Dockerfile), following
   the archive and packages in [build.json](build.json). Produce and retain
   `crio`, `pinns` and their `SHA256SUMS`.
2. Start [test-vm.yaml](test-vm.yaml) with Lima VZ in its own temporary
   `LIMA_HOME`; use `limactl start --plain --mount-none --name=mounttest`.
   The validated recipe uses the ARM64 image. Transfer only the three build
   outputs and this directory's guest scripts and Pod manifest to
   `/tmp/saf-cri-candidate` in the guest.
3. Run `guest-packages.sh`, `guest-runtime.sh`, `guest-kubeadm.sh`, and
   `guest-mount-probe.sh` in that order with Bash inside the guest. The
   Kubernetes package feed is signed and the recipe verifies the observed
   public key fingerprint. Guest package and artifact digests are in
   `runtime.json`. The bootstrap skips token creation and keeps admin
   credentials inside the guest.
4. Run `guest-mount-probe.sh` again for a fresh Pod. Compare the two Pod
   observations, verify each namespace was removed, and remove the disposable
   guest using its dedicated Lima instance directory.

## Primary references

- [Kubernetes v1.37 bind mount options](https://kubernetes.io/docs/tasks/configure-pod-container/configure-bind-mount-options/)
- [Kubernetes v1.37 kubeadm install](https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/install-kubeadm/)
- [Kubernetes enhancement proposal 5855](https://www.kubernetes.dev/resources/keps/5855/)
- [CRI-O v1.37.4 release](https://github.com/cri-o/cri-o/releases/tag/v1.37.4)
