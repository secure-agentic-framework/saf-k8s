# SAF-K8S-0303-004 MAC profile generation from runtime behavior

Run `python3 lab.py test SAF-K8S-0303-004` with the catalog revision in the
verified result. A restricted Kind Job starts a disconnected ARM64 Linux guest.
In that guest, AppArmor records actual file opens. A separate seccomp recorder
gets kernel notifications for three selected, harmless system calls from an
owned child process. Each proof compares the recorded operations with a separate
immutable approval list.

The first captures include an incidental operation and miss an approved recovery
operation. The initial enforcing policies reproduce the recovery denial. After
the recovery exercise, the two generated policies retain their approved normal
and recovery operations, and the enforcing probes reject the incidental ones.
AppArmor rollback removes the fixture profile. Seccomp recovery uses a fresh
unfiltered fixture process. The checks retain the scoped input and generated
profile digests in `mac-recording-observations.json`.

## Adopter checks

Pin the workload and dependencies and the collector, runtime, kernel, architecture,
and policy versions. Determine which event classes the selected recording
mechanism actually sees. Exercise one expected event, normal and infrequent
recovery paths, and an incidental operation that must remain outside the policy.
Correlate these observations with the workload and review intended operations
before accepting a generated or curated candidate.

Verify the exact candidate under the real mechanism with allowed and denied
probes, record a reviewed rollback target, and exercise recovery. Seccomp
notifications in this example are collected for fixed argument-free synthetic
calls only. The app-level collector starts and observes its own child. Taken
together, the tests cover AppArmor file opens and three Linux syscalls.
Other SELinux classes, additional mediation mechanisms, and broader policy coverage
are properties of the deployment being adopted.

- [Linux kernel seccomp filters and notifications](https://docs.kernel.org/userspace-api/seccomp_filter.html)
- [Linux kernel AppArmor documentation](https://docs.kernel.org/admin-guide/LSM/apparmor.html)
- [NIST SP 800-53 Revision 5.2.0 catalog release](https://github.com/usnistgov/oscal-content/releases/tag/v1.5.0)

## SELinux recording and rule generation

A separate restricted Job boots an isolated SELinux guest with the pinned
Debian reference policy. One synthetic subject reads three harmless labeled
files with matched discretionary permissions. The fixture collects attributable
SELinux AVCs, intersects the observed types with the independently specified
allowlist, and installs only the generated file rules. It verifies initial and
final enforcing outcomes, and then reloads the exact saved baseline policy
and checks that the baseline decisions return. The fixture retains the generated rule
digests and raw matched AVCs in `selinux-recording-observations.json`.

For an adopted SELinux policy, review the actual subject and object contexts,
access classes, enforcement and audit modes, and any event suppression before
relying on the observed coverage. Verify the final approved module and rollback
on the applicable platform with expected allowed and denied operations.

- [SELinux modes and AVC records](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
