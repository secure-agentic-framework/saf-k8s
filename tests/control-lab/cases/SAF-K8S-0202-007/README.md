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
