# SAF-K8S-0201-009 Effective kubelet systemd hardening

From the framework root, run `python3 tests/control-lab/lab.py test SAF-K8S-0201-009`.
The IPv4 Kind example compares the running kubelet and one short probe invoked
by the same systemd unit at startup. It records the exact capability change,
`NoNewPrivs`, and the effective read-only mount for an owned marker. The probe
reads that marker, observes the denied write, writes to an allowed path, and
tests the selected socket families by opening sockets without connecting.
The unit keeps Unix and IPv4 socket creation while the example denies IPv6.
The same kubelet then starts a fresh restricted ConfigMap workload. Removing
the fixture drop-in restores the original effective state.

## Verify your implementation

1. Inventory the approved OS/node image, kernel, systemd, Kubernetes, runtime,
   CNI, devices, volume drivers and node services. Identify the main unit,
   ordered drop-ins and referenced configuration. Use `systemctl cat` and
   `systemctl show` to reconstruct effective settings in an authorized
   environment and retain only reviewed fields.
2. Write down the required capability set, mount operations and paths, and
   socket families before choosing restrictions. Include DNS, the API
   connection, the CRI socket and volume and device access where supported.
   Document the approval and verification steps for any additional permissions.
3. Rehearse the candidate on a disposable or authorized staging node. Inspect
   `/proc/<MainPID>/status` for `NoNewPrivs` and `CapBnd`, and the process's
   mount table for the intended path flags. Check the full expected capability
   bound. Test a safe write denial and a permitted path associated with the
   policy, using an owned marker. Use harmless socket creation to check
   applicable family restrictions and account for activated and inherited
   descriptors separately. The IPv4 example's family choice is specific to
   its declared dependencies.
4. Confirm new node and workload activity under the verified policy after
   restart. Exercise the duties the policy touches, including the declared
   CRI, networking, mount and device paths. Record the loaded version,
   observed kernel results, fresh workload evidence, and a rollback or
   recovery rehearsal.
5. For provider-operated node pools, verify comparable controls and
   compatibility using service, version and pool-specific evidence. Record
   unavailable prerequisites and approved provider or workload exceptions.

`ReadOnlyPaths` shows the selected path operation. Assess mount propagation
and privileged remount authority when choosing production restrictions.
`RestrictAddressFamilies` covers socket creation. Existing descriptors and
other IPC paths remain subject to their own verification.

- [systemd 252 execution settings](https://www.freedesktop.org/software/systemd/man/252/systemd.exec.html)
- [systemd 252 service startup hooks](https://www.freedesktop.org/software/systemd/man/252/systemd.service.html)
- [Kubernetes v1.36 kubeadm kubelet integration](https://v1-36.docs.kubernetes.io/docs/setup/production-environment/tools/kubeadm/kubelet-integration/)
