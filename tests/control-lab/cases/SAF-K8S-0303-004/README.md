# SAF-K8S-0303-004 AppArmor recording and policy generation

Run `python3 lab.py test SAF-K8S-0303-004` using the catalog revision recorded with
the verified result. A restricted Kind Job uses a disconnected AppArmor guest.
The recorder captures actual open events for synthetic fixture files. A
bounded renderer intersects those observations with an immutable approval
list, emits an exact fixture policy, and checks enforcing behavior.

The first capture contains an incidental operation and misses an approved
recovery path. After exercising recovery, the generated policy keeps approved
startup and recovery and excludes the incidental operation. This fixture
covers AppArmor file opens and an intentionally restricted rule renderer.
Seccomp, SELinux, other AppArmor mediation classes, and production policy
exercise require separate evidence.

- [AppArmor profile modes](https://apparmor.dev/man/apparmor.d/)
- [Kubernetes Linux kernel security constraints](https://kubernetes.io/docs/concepts/security/linux-kernel-security-constraints/)
