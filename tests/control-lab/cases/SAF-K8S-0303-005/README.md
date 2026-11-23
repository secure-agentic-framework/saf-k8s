# SAF-K8S-0303-005 AppArmor observation before enforcement

Run `python3 lab.py test SAF-K8S-0303-005` from the lab directory with the catalog
revision recorded in the verified result. A restricted Kind Job boots a
disconnected ARM64 guest and loads the exact AppArmor profile bytes delivered
by an immutable ConfigMap. It verifies the loaded modes and checks the same
owned reads before policy, in complain mode and in enforcing mode.

Complain-mode coverage requires an attributable would-be denial audit event.
The case also records the decision for an explicit deny in the pinned
kernel/compiler combination, then checks that enforcing mode denies both
synthetic canaries and preserves the approved read. Removing the fixture
profile restores both reads. Review the actual platform and audit pipeline
for production. Seccomp and SELinux mode behavior require separate evidence.

- [AppArmor profile modes and explicit deny handling](https://apparmor.dev/man/apparmor.d/)
- [Linux kernel seccomp filter documentation](https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html)
