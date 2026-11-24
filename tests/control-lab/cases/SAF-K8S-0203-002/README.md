# SAF-K8S-0203-002 — Kernel parameter hardening via sysctl

```sh
python3 lab.py test SAF-K8S-0203-002 --docker-context desktop-linux
```

The case uses a fresh mount-free Debian ARM64 guest. It installs and applies an
exact stale profile, then requires the observed effective values to match that
profile, including `kernel.kptr_restrict=1` where the approved value is `2`.
It replaces the stale drop-in with the approved profile, verifies all five
selected values through `/proc/sys` and introduces runtime-only drift while
leaving the approved file intact. It then stops and starts the same guest. After
boot, it requires a different kernel boot ID, the unchanged approved drop-in,
a successful active `systemd-sysctl.service`, and the exact effective values
without reapplying configuration.

Forwarding and `rp_filter` values are recorded read-only by guest scope,
including `all`, `default`, and available interfaces. They are observations,
not pass/fail policy values: node role, CNI routes, asymmetric or policy
routing, and provider design determine the approved settings. The `tcp_syncookies`
value is a configuration observation; it is not evidence of general SYN flood
mitigation.

Two running Pods on a separate Kubernetes v1.36.1 Kind node request different
safe values of `kernel.shm_rmid_forced`. Each reads back its own value. The
guest configuration and the Pod IPC configuration are distinct deployment
surfaces.

The guest profile and reboot evidence do not establish production node-pool
coverage. Adopters must validate profile applicability and effective values by
node role, OS/kernel and interfaces after rollout and reboot; check normal CNI
and workload health; and review RDMA and other routing requirements. Where a
managed provider controls nodes, obtain provider evidence that identifies the
covered pools, profile revision, exceptions, effective keys/values, and
rollout/reboot coverage. Do not apply universal forwarding or `rp_filter`
values across roles. This recipe uses macOS ARM64 with Lima VZ and a local
Docker context.

[Linux kernel sysctls](https://docs.kernel.org/admin-guide/sysctl/kernel.html) ·
[Linux network sysctls](https://docs.kernel.org/networking/ip-sysctl.html) ·
[Kubernetes v1.36 sysctl scope](https://v1-36.docs.kubernetes.io/docs/tasks/administer-cluster/sysctl-cluster/)
