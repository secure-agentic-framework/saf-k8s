# SAF-K8S-0302-005 — Exact workload profile and container hardening

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0302-005 --docker-context desktop-linux
```

A CPU-only fixture compares a writable root filesystem and RuntimeDefault
seccomp with non-root execution, a read-only root filesystem, and an exact
node-local profile. The example profile returns EPERM for the harmless
`uname` syscall. The running fixture confirms process UID, seccomp mode,
the blocked call and EROFS, and checks that `getpid` and a bounded
`emptyDir` write still work. It needs no host root access or physical GPU;
the root UID observation is inside the disposable baseline container.

Restricted Pod Security Admission accepts a non-root dry-run with
RuntimeDefault and a writable root filesystem. An additional validating
policy rejects that same request and permits only the named Localhost profile
and read-only root filesystem for regular and init containers at Pod CREATE,
and ephemeral containers at `pods/ephemeralcontainers` UPDATE. Server-dry-run
positive samples cover compliant regular, init, and ephemeral containers;
negative samples show a writable root filesystem and a non-exact profile
being denied on both new container paths. Ephemeral-container requests target
the case-owned confined Pod and do not persist changes. Normalized results are
retained as `cpu-profile-admission-observations.json` through `lab.evidence`.

The profile is a syscall enforcement fixture with a default-allow rule. It
provides no production profile baseline and makes no accelerator measurements.
The disposable exercise confirms profile mechanics only; it does not establish
GPU, RDMA, driver, device-plugin, CDI, or workload compatibility. The runner
removes the disposable node and test objects.

## Adopter verification

For every node eligible to run the workload, record its node identity,
Kubernetes and kernel versions, CRI/runtime, architecture, kubelet seccomp
profile root, and scheduling labels/taints. Verify that the exact approved
Localhost profile path exists under that kubelet profile root on each eligible
node and that its content digest matches the approved artifact. Confirm profile
distribution and update behavior after node replacement or upgrade; a profile
on one node does not establish availability on another. For Localhost AppArmor,
verify the approved profile is loaded in enforce mode on each eligible node
and confirm the test process is confined under the intended profile. Retain the
admission policy and binding generation/status and exercise positive and
negative server-dry-run requests for regular, init, and ephemeral containers.

For device/RDMA workloads, use only authorized adopter hardware and the actual
driver, device-plugin or CDI, runtime, and workload image combinations in
scope. On each materially distinct combination, check the workload's required
device access, shared-memory and RDMA behavior alongside a harmless operation
denied by the chosen profile and the read-only-root/writable-volume behavior. Record those results
as adopter evidence and mark untested combinations explicitly. The portable
CPU fixture supplies none of those measurements and its deny-`uname` profile
must not be adopted as a production profile.

- [Kubernetes v1.36 seccomp](https://v1-36.docs.kubernetes.io/docs/tutorials/security/seccomp/)
- [Kubernetes v1.36 AppArmor](https://v1-36.docs.kubernetes.io/docs/tutorials/security/apparmor/)
- [Kubernetes v1.36 Pod Security Standards](https://v1-36.docs.kubernetes.io/docs/concepts/security/pod-security-standards/)
