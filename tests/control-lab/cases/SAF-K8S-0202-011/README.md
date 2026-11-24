# SAF-K8S-0202-011 — Effective node mandatory access control

```sh
python3 lab.py test SAF-K8S-0202-011 --docker-context desktop-linux
```

The Kind test observes Kubernetes admission before and after an approved
profile is required. It checks regular and ephemeral container overrides,
native refusal of an unavailable profile, and a permitted marker workload.

The independent OCI test uses Apple Silicon, macOS Virtualization.framework
and Lima 2.0 or newer with the specified digest-pinned Debian guest. It uses
Debian's signed package repositories to install runc and static BusyBox.
The runner starts the guest with no host mounts. A non-root OCI process with
empty capability sets writes two equivalent markers before loading policy.
With the intended AppArmor profile enforced, the process reports its actual
label, writes the permitted marker and cannot write the other. Both writes
succeed again after the profile is removed. The runner deletes the test VM.

## Verify an adopter deployment

1. Inventory every applicable pool's kernel, active LSM, policy source,
   runtime and version. Verify the intended AppArmor profile is loaded in
   enforce mode, and compare its reviewed source and digest with the assigned
   policy. Retain the loaded profile and applicable node inventory.
2. Observe the protected workload's effective process profile and its bound
   node. Use safe markers with the same file permissions to check the
   intended allow and deny outcomes. Retain the actual labels, observed
   decisions, attributable kernel/audit events where applicable, and any
   drift or failure.
3. Check admission for the chosen namespace or trusted workload scope,
   including container, init-container and ephemeral-container overrides.
   Document how eligible nodes are selected, who attests to profile readiness,
   and how stale labels, replacement nodes and existing workloads are handled.
4. For SELinux, verify enforcing mode, the effective process and file
   labels, policy identity, and the intended allowed operation and denial.
   Retain the corresponding access decision or AVC. The OCI case exercises
   AppArmor, and the SELinux procedure applies where SELinux is selected.
5. For managed services or unsupported node profiles, retain provider and
   version-specific evidence, the approved exception owner and expiration,
   and the remaining unverified scope.

- [Kubernetes v1.36 AppArmor confinement](https://v1-36.docs.kubernetes.io/docs/tutorials/security/apparmor/)
- [Kubernetes v1.36 Linux kernel security constraints](https://v1-36.docs.kubernetes.io/docs/concepts/security/linux-kernel-security-constraints/)
- [OCI Runtime Specification v1.2.1 process configuration](https://github.com/opencontainers/runtime-spec/blob/v1.2.1/config.md)
