# SAF-K8S-0203-012 — Effective Linux kernel module policy

```sh
python3 lab.py test SAF-K8S-0203-012 --docker-context desktop-linux
```

A restricted Kind Job boots isolated ARM64 QEMU guests with the same
pinned Linux kernel and two stock modules. Without the freeze, the
fixture loads and unloads modules. The governed guest loads its approved
loop module first, sets `kernel.modules_disabled`, and checks that the
same load and unload operations are denied and the freeze stays set.
A new loop device reads a marker from an owned image while the policy
is active. A fresh guest boot starts unfrozen, initializes the approved
module, reapplies the freeze, and repeats the operating and denied cases.

## Verify deployment applicability and evidence

1. Record the exact Linux image, kernel version and configuration, node
   role, owner, provider support, and the approved module model for each
   applicable pool. Distinguish built-in drivers, packaged modules and
   loaded modules, and review the functions that rely on each.
2. Where the profile freezes modules, verify the running
   `kernel.modules_disabled` value after initialization. Exercise required
   network, storage, runtime, monitoring or device functions on approved
   disposable replacement nodes. Retain allowed and denied observations
   from after the approved loading window and after fresh boot or upgrade.
3. Where dynamic loading is required, confirm the supported kernel
   signature enforcement mode and effective trust keys. Retain evidence
   of successful approved loading and denial by the selected policy
   using fixture-only modules. Track key ownership, renewal and exceptions.
   Per-module policy and already-loaded capabilities require their own
   verification. Test autoload controls under a supported modprobe or LSM
   policy as applicable.
4. For opaque pools, collect corresponding provider evidence scoped to the
   exact image and module path. Record unsupported settings, exception
   scope and expiry, and approved recovery or rollback behavior.

The runnable fixture exercises the kernel-wide freeze and retained loop
operation. Other module policies and provider-specific operations have
their own adoption evidence.

[Linux v6.12 modules_disabled](https://docs.kernel.org/6.12/admin-guide/sysctl/kernel.html#modules-disabled) ·
[Linux v6.12 module signatures](https://docs.kernel.org/6.12/admin-guide/module-signing.html) ·
[Kubernetes v1.36 module autoload controls](https://v1-36.docs.kubernetes.io/docs/tasks/administer-cluster/securing-a-cluster/#preventing-containers-from-loading-unwanted-kernel-modules)
