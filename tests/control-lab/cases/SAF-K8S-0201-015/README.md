# SAF-K8S-0201-015 Node-level kubelet file audit

Run on a Mac with Docker, kind, kubectl and Lima 2.0 or newer. Lima uses
Virtualization.framework and a digest-pinned Debian 13 guest image. The guest
installs Debian's signed `auditd` package at the version in `audit_fixtures.py`.

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0201-015 --docker-context desktop-linux
```

Kind checks the expected kubelet file and directory types through metadata.
An independently booted guest with no host mounts checks Linux Audit using
inert files. A heartbeat establishes that audit collection works while the
other paths are unwatched. The guest loads the selected watches through
`rules.d`. A systemd timer samples the actual loaded rules, detects a deliberately
removed watch, and confirms restoration from the persistent rules on a separate
invocation. The same fixture then observes successful read and write events
with kernel serials, syscall access modes, and exact synthetic markers.

The retained receipt records the guest kernel and userspace builds, architecture,
test and guest configuration digests, scheduled invocation identities, marker
events, kernel lost-event status, and cleanup. The guest uses Linux Audit's
legacy file watches. The upstream arm64 issue describes a different syscall and
path-rule syntax and identifies affected userspace builds. Exercise the chosen
form with observed events on the deployed package and architecture.

## Verify your implementation

1. Inventory in-scope node pools, OS, kernel and audit package builds. Determine
   effective kubelet config, kubeconfig, and credential paths from approved
   provisioning and runtime metadata. Record any provider evidence and
   unsupported scope.
2. Compare persistent audit configuration with the effective loaded rule set.
   Identify coverage of the expected read and write events and canonical
   paths, including symlinks, rotation and atomic replacement where applicable.
   Evaluate rule cost, backlog capacity, and event loss for the authorized node
   population.
3. Rehearse using approved synthetic files and a collector canary. Verify that
   events correspond to the intended rule, path, syscall, access mode, and
   process. Keep event identifiers and outcomes without retaining credentials
   or file contents.
4. Test recurring coverage checks after provisioning changes and restarts.
   Observe a logged missing-rule result and a definite recovery finding. Record
   schedule, scope, timestamps and ownership. For a provider-managed equivalent,
   retain service-specific evidence for the same event classes and cadence.

- [Linux Audit rule reference](https://github.com/linux-audit/audit-userspace/blob/v4.0.5/docs/audit.rules.7)
- [Linux Audit arm64 rule-loader issue](https://github.com/linux-audit/audit-userspace/issues/496)
- [Debian 13 auditd package](https://packages.debian.org/trixie/auditd)
- [systemd timer reference](https://www.freedesktop.org/software/systemd/man/257/systemd.timer.html)
