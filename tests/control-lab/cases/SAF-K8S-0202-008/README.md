# SAF-K8S-0202-008 — Container runtime socket access protection

```sh
python3 lab.py test SAF-K8S-0202-008 --docker-context desktop-linux
```

On the disposable Kind node, the case inspects the canonical rootful
containerd socket path and each parent, reads native POSIX access ACL
metadata, and checks pathname write access as an unrelated UID and GID.
The test uses metadata and permission checks on the real runtime socket.

A separate Unix echo service tests the effects of directory traversal and
socket mode. It also shows that a non-owner with the approved supplementary
group can echo and the same identity without that group is denied. The case
uses a server dry-run with an inert hostPath socket reference to observe
Pod Security Admission before and after Baseline enforcement. A compliant
marker Pod reaches Ready.

## Verify an adopter deployment

1. Inventory runtime, kubelet CRI endpoint, node OS, provider, service owner
   and effective daemon identity for each pool. Resolve the socket path and
   aliases from the effective service and socket units. Inspect each parent,
   the final object type and the expected owner, group and mode. Retain
   dated metadata and the rendered service revision.
2. Review applicable access ACLs and effective group membership, including
   directory service groups and supplementary groups. Verify parent paths
   restrict traversal and modification to the expected principals as
   appropriate. Check the origin of permissions on recreation, including
   service or socket settings and directory default ACLs. With an approved
   unrelated test identity, check pathname permissions without issuing a
   runtime request. Retain expected and observed access decisions.
3. For a rootless runtime, verify the dedicated daemon identity, its user
   service and the actual runtime directory. Review approved administrator
   access. For a managed runtime, obtain service, version and node-pool
   evidence for the provider-operated path and assess customer-visible controls.
4. Inspect namespace policy, approved exemptions and deployed workload volume
   specifications. Cover socket aliases, bind mounts of parent directories,
   and privileged workload or node access. Use admission dry-runs with
   inert marker paths to test permitted and denied decisions. Retain the
   rejection reason, policy revision and proof that a compliant Pod runs.
5. Recheck after a node image, runtime or admission-policy change. Record
   unknown ownership, ACLs, provider settings or workload exceptions as
   unverified.

- [Linux pathname socket permissions](https://man7.org/linux/man-pages/man7/unix.7.html)
- [Kubernetes v1.36 Pod Security Standards](https://v1-36.docs.kubernetes.io/docs/concepts/security/pod-security-standards/)
- [containerd operator security guidance](https://github.com/containerd/containerd/blob/main/docs/security/OPERATOR_GUIDELINES.md)
