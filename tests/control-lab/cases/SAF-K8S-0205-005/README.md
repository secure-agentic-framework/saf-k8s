# Verify signed guest BPF load and attachment lifecycle

The case keeps its existing five checks: ordinary and init-container capability
admission comparisons, the restricted denial and changed-byte signature
comparison, the live non-root/zero-capability Job, approved marker digest
verification, and the accepted unattached `socket_filter` load/inventory
lifecycle. The added sixth grouped check signs a second harmless BPF object,
loads it in the same disposable guest, attaches it only to the case-owned
cgroup-v2 child `/sys/fs/cgroup/saf-0205-005`, and detaches it after one benign
read of `/proc/sys/kernel/hostname` by a child placed in that cgroup. A
one-entry map starts at zero, records a positive invocation count during the
owned child probe, and keeps the same count when the probe repeats after detach.
The raw receipt preserves each count. The script
also checks the exact program type, attached name, and cleanup of its pin, map,
and cgroup.

The runner creates an ephemeral key outside Kubernetes and signs both exact
objects extracted from the locally built fixture image. Kubernetes receives
only the public key, detached signatures, and digests in a fixture-owned
immutable ConfigMap; private key material is removed before the Job starts.
Inside the guest the signed attachment object is verified before load. The
original `marker.o` source and unattached `socket_filter` behavior are retained.

The guest is the pinned Debian ARM64 image with Linux 6.12.118, QEMU, and
bpftool 7.5.0. The guest has no network device (`-nic none`). The new hook is
used as a bounded observation fixture, not as a sysctl security policy. Linux
documents `BPF_PROG_TYPE_CGROUP_SYSCTL` as a cgroup hook invoked for reads and
writes and cautions against using it to restrict sysctl access:
[Linux 6.12 cgroup sysctl BPF documentation](https://docs.kernel.org/6.12/bpf/prog_cgroup_sysctl.html).
The command shape and `cgroup_sysctl` attachment type follow the pinned
[bpftool v7.5.0 cgroup documentation](https://github.com/libbpf/bpftool/blob/v7.5.0/docs/bpftool-cgroup.rst).

For deployment, separately inventory the actual kernel, loader, provider
components, trust source, and policy boundary. Verify actual load authorization,
approved signer enrollment/rotation, attached-program inventory, attributable
load/attach/detach decisions, event delivery, monitor health, and retention in
the adopted environment. This portable fixture demonstrates only a signed
benign object lifecycle and one guest-local attachment event; it does not prove
cluster-node BPF enforcement, provider monitoring completeness, refused-load
telemetry, or production trust governance.

Run the parent lab command from the framework checkout. The runner creates
and cleans up the owned Kubernetes cluster and the disconnected guest.
