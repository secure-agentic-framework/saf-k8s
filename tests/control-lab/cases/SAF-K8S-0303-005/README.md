# SAF-K8S-0303-005 MAC observation before enforcement

## Adopter guide

Run `python3 lab.py test SAF-K8S-0303-005` from the lab directory with the catalog
revision recorded in the verified result. This case is an isolated, disconnected
ARM64 guest fixture launched by the lab's restricted Kind Job. The guest kernel,
and QEMU/userspace build recipe are retained in `Dockerfile`. The image
label binds the recipe and `seccomp-proof.c` source digest. The AppArmor profile
bytes continue to be supplied through the immutable ConfigMap and independently
matched to the in-guest profile input digest.

The inherited AppArmor proof remains: it checks both owned reads before policy,
complain-mode allowance plus an attributable implicit-denial audit record, the
explicit-rule decision under the pinned compiler/kernel pair, enforcing denial
of both canaries while the approved read remains available, and recovery after
removing the profile.

The separate seccomp proof loads the filter compiled from `seccomp-proof.c` in
two fresh processes. Its ARM64 policy kills on an unexpected architecture,
returns `SECCOMP_RET_LOG` for the harmless `getpid` probe in observation mode,
and allows the other syscalls needed by this fixture. A second process uses the
same policy matrix with that one action translated to `SECCOMP_RET_ERRNO | EPERM`.
It requires the probe to fail with `EPERM` while the ordinary `getuid` operation succeeds. A third,
fresh process succeeds without the filter to demonstrate process-restart
recovery; seccomp filters cannot be removed from an already filtered process.
The observation result alone is not audit proof: the guest must also show one
kernel `type=1326` SECCOMP audit record matching the probe PID, ARM64 `getpid`
number (`syscall=172`) and LOG action (`code=0x7ffc0000`). The checker captures
that record separately in `mac-audit-observations.json`.

### Audit and runtime prerequisites

The fixture requires an ARM64 kernel with `CONFIG_SECCOMP`,
`CONFIG_SECCOMP_FILTER`, and `CONFIG_AUDIT`, booted with kernel auditing enabled
(`audit=1`). It requires `log` in `/proc/sys/kernel/seccomp/actions_avail` and
`actions_logged`; only the disposable guest changes the latter if needed. The
guest init process must be able to read the kernel audit ring (`dmesg` here).
An adopter using an existing guest can instead collect the same mechanism
record from its configured audit daemon/journal, but must preserve and validate
the raw SECCOMP record, including PID, architecture, syscall, and action code.
If audit logging is unavailable, filtered out, rate-limited, or inaccessible,
the observation is inconclusive even if `getpid` succeeds or a tool reports
“log” mode. Production collection must also prove delivery, retention, loss
handling, clock/source identity and workload attribution.

The filter is intentionally a tiny representative policy, not a production
allowlist. The fixture's ordinary coverage is the `getuid`, output and process-exit path. Replace it with the exact reviewed workload
filter, architecture/ABI matrix and representative workload operations before
adoption. The pinned Debian trixie package/kernel and QEMU ARM64 TCG run are
fixture assumptions, not claims about other kernels or container runtimes.

Complain-mode coverage requires an attributable would-be denial audit event.
The seccomp proof is a distinct kernel-filter and audit-event check. SELinux
permissive/enforcing behavior, SELinux AVC collection, the production audit
pipeline, platform-specific profile delivery, runtime defaults, workload
coverage and rollback need separate evidence on each supported platform.

- [AppArmor profile modes and explicit deny handling](https://apparmor.dev/man/apparmor.d/)
- [Linux kernel seccomp filter documentation](https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html)
- [Linux seccomp audit logging details](https://man7.org/linux/man-pages/man2/seccomp.2.html)
