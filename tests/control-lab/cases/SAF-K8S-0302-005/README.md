# SAF-K8S-0302-005 — Exact workload profile and container hardening

```sh
python3 lab.py test SAF-K8S-0302-005 --docker-context desktop-linux
```

A CPU-only fixture compares a writable root filesystem and RuntimeDefault
seccomp with non-root execution, a read-only root filesystem, and an exact
node-local profile. The example profile returns EPERM for the harmless
`uname` syscall. The running fixture confirms process UID, seccomp mode,
the blocked call and EROFS, and checks that `getpid` and a bounded
`emptyDir` write still work.

Restricted Pod Security Admission accepts a non-root dry-run with
RuntimeDefault and a writable root filesystem. An additional validating
policy rejects that same request and permits the named Localhost profile
and read-only root filesystem for the fixture's regular containers.

The profile is a syscall enforcement fixture with a default-allow rule. It
provides no production profile baseline. Validation on eligible GPU or RDMA
nodes, built-in or custom profile compatibility, and deployment controls for
init and ephemeral containers need separate evidence. The runner removes
the disposable node and test objects.

- [Kubernetes v1.36 seccomp](https://v1-36.docs.kubernetes.io/docs/tutorials/security/seccomp/)
- [Kubernetes v1.36 Pod Security Standards](https://v1-36.docs.kubernetes.io/docs/concepts/security/pod-security-standards/)
