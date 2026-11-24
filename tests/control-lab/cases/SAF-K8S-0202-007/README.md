# SAF-K8S-0202-007 — Pod user namespace isolation

Run the case against the current catalog from the SAF-K8S checkout.

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0202-007 --docker-context desktop-linux
```

The runner creates a disposable Kubernetes v1.36.1 Kind cluster. One BusyBox
workload uses the default user namespace. A second explicitly sets
`spec.hostUsers: false`. Both run a benign command as workload UID and GID zero.
The case reads each workload's kernel UID and GID mappings and requires the
opted-in workload's root IDs to map to nonzero node IDs. It corroborates the
mapping and user namespace of each exact fixture process through the owned
Kind node and checks that the node itself uses identity UID and GID ranges.
A namespace-scoped admission policy blocks both omission and explicit
`hostUsers: true` after the control is applied. The opted-in workload reaches
Ready, and an ungoverned namespace admits the comparison dry-run.

The separately reported Node field `status.nodeInfo.runningInUserNamespace`
is absent in the pinned v1.36.1 profile. The case records that value as unknown
and bases Pod isolation on the live Pod mapping. Retained evidence is in
`pod-id-mappings.raw.json` and the command transcript.

Kubernetes v1.36 made Linux Pod user namespaces stable. Runtime, kernel,
filesystem, and workload compatibility still govern deployment. Production
pool coverage, exception authorization, compensating controls, and any claim
of node-level rootless operation require separate evidence. SAF-K8S-0202-012
covers rootless node components and workload placement where applicable.

- [Kubernetes v1.36 Pod user namespaces](https://v1-36.docs.kubernetes.io/docs/concepts/workloads/pods/user-namespaces/)
- [Kubernetes v1.37 rootless node operation](https://kubernetes.io/blog/2026/09/04/kubernetes-v1-37-rootless-beta/)

## Verify your implementation

1. Inventory each Linux node pool and workload profile. Record the API server
   and kubelet versions, CRI and OCI runtimes, kernel, kubelet Pod storage
   filesystem, and volume types used by each profile. Check the release-specific
   prerequisites for user namespaces and ID-mapped mounts. For v1.36, workloads
   that use other host namespaces or raw block devices cannot opt in. An
   unsupported filesystem or volume configuration also needs a disposition.
2. Review the effective Pod admission policy and the namespaces and workload
   paths it covers. From an approved representative environment, submit
   equivalent Pod requests with the field omitted, set to true, and set to
   false. In the enforced scope the first two must receive a denial identifying
   the intended policy, while the explicit opt-in must pass. Exercise the policy
   from a representative workload submission path and verify each allowed
   exception's scope and expiry. Test allowed workloads through scheduling,
   readiness, and representative volume behavior.
3. Check running Pod mappings. Identify the Pod UID, node, container identity,
   and corresponding runtime process using approved evidence from the node
   operator. Read `/proc/self/uid_map` and `/proc/self/gid_map` from the approved
   fixture or workload when available. Corroborate with `/proc/<pid>/uid_map`,
   `/proc/<pid>/gid_map`, and the user namespace identifier for that same
   process, with the observer namespace recorded. Both workload root IDs must
   resolve to nonzero IDs in the intended host context.
4. On a node that itself uses a user namespace, use a trusted operator
   observation from the outer host namespace or compose the confirmed
   UID and GID ranges through every parent boundary. Each mapping row
   describes an input start, an output start, and the number of IDs. A
   matching input ID maps to the output start plus its offset in that
   range. Capture the reader and target namespaces with each observation. A
   read from the target namespace reports the parent range. A read from a
   different namespace reports mappings visible from the reader namespace.
   Treat an unmapped range or the unsigned unmapped marker 4294967295 as
   missing evidence. Record the host mapping as unverified if either ID
   cannot be resolved to the initial namespace.
5. Retain the test requests and verdicts, workload identity and readiness,
   versions and volume support, sanitized map observations, and any exception
   scope, expiry, approver, and compensating controls. Recheck when the node
   image, runtime, policy scope, or workload volume profile changes.

- [Linux user namespace mapping semantics](https://man7.org/linux/man-pages/man7/user_namespaces.7.html)
