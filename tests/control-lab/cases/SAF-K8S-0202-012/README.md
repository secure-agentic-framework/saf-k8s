# SAF-K8S-0202-012 — Rootless node verification and placement eligibility

```sh
python3 lab.py test SAF-K8S-0202-012 --docker-context desktop-linux
```

The command above runs from this directory's control-lab root in the SAF-K8S
framework. In the separate validation repository, pass the release index with
`--catalog-index catalog/additions/SAF-K8S-0202-012.json`.

Use macOS ARM64 with local rootful Docker, Kind, kubectl, and Lima VZ.
The case creates a pinned Kubernetes v1.37.0 Kind cluster and a second
Kind cluster in its own mount-free Debian ARM64 guest. The guest installs
Podman and runs the second cluster under its dedicated unprivileged user
with delegated IDs and cgroup v2. Both clusters and the guest are removed
after the run. Upstream package and image downloads may be required.

On the ordinary cluster the kubelet reports false and its process has
the initial UID map. In the Linux guest the kubelet reports true, and
independent kernel observations show the intended maps and the same
noninitial user namespace for kubelet, containerd, kube-proxy, and kindnetd.

The scheduler leaves a Pod awaiting a protected label Pending. After the
fixture administrator applies the verified label the same Pod runs and
emits the expected marker. Removing the label leaves the next Pod Pending.
The case applies the label administratively after verification. Production
approval, reconciler freshness, existing-Pod eviction, deployment
compatibility, and hardware or external attestation remain separate.

[Kubernetes v1.37 rootless mode](https://kubernetes.io/blog/2026/09/04/kubernetes-v1-37-rootless-beta/) ·
[Kind rootless providers](https://kind.sigs.k8s.io/docs/user/rootless/) ·
[Kubernetes node isolation and labels](https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/#node-isolation-restriction)
