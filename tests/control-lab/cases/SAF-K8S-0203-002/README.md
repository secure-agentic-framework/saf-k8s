# SAF-K8S-0203-002 — Kernel parameter hardening via sysctl

```sh
python3 lab.py test SAF-K8S-0203-002 --docker-context desktop-linux
```

The case reads effective kernel values in a fresh mount-free Debian ARM64
guest. It confirms the expected drop-in is absent and distinguishes a stale
profile using fixture data. The administrative step installs the approved
drop-in inside that guest and reads the five effective values from
`/proc/sys`. The profile covers ASLR, kernel information exposure, core
dumps after privilege transitions, and the SYN-cookie setting.

Two running Pods on a separate Kubernetes v1.36.1 Kind node request different
safe values of `kernel.shm_rmid_forced`. Each reads back its own value. The
guest configuration and the Pod IPC configuration are distinct deployment
surfaces.

Production profiles, routing and network behavior, reboot persistence, CNI and
RDMA requirements, and managed-provider attestations require separate evidence.
This recipe uses macOS ARM64 with Lima VZ and a local Docker context.

[Linux kernel sysctls](https://docs.kernel.org/admin-guide/sysctl/kernel.html) ·
[Linux network sysctls](https://docs.kernel.org/networking/ip-sysctl.html) ·
[Kubernetes v1.36 sysctl scope](https://v1-36.docs.kubernetes.io/docs/tasks/administer-cluster/sysctl-cluster/)
