# SAF-K8S-0302-007 — Group identity and volume permissions

This case pins an exact fsGroup and exact supplementary groups, and sets
supplementalGroupsPolicy to Strict. Before applying the policy, the same inert
requests are admitted. After applying it, unsafe group IDs, an out-of-scope
mount path, hostPath, and an unapproved PVC are rejected by server dry-run.

The case runs nonroot Pods with a shared emptyDir and with a static local volume
claimed through the approved PVC. A specific node directory belongs only to the
disposable fixture. Each workload reports the approved process group set and
volume GID. One container writes a synthetic marker to the designated workload
volume and its peer can read it. The same identity is denied writes to a
protected read-only ConfigMap mount, and its sentinel is unchanged.

The Kubernetes security context distinguishes supplementary process groups from
fsGroup ownership and permission handling on supported volumes. The case
verifies two volume mechanisms. CSI ownership behavior and shared production
storage need separate deployment evidence.

- [Kubernetes v1.36 security context](https://v1-36.docs.kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [Kubernetes v1.36 volume types](https://v1-36.docs.kubernetes.io/docs/concepts/storage/volumes/#local)

The revised catalog also runs a separate v1.37.0 kind profile. Use kind
v0.33.0 or compatible for that profile. Its Linux kubelets use opposite
`EmptyDirVolumeMode` gate values while the v1.37 API server retains the
`emptyDir.mode` field. The probe compares mounted modes and checks actual
write decisions from nonroot Pods. It also checks how `fsGroup` changes
(emptyDir) ownership and effective permission bits on an enabled kubelet.
The alpha gate is disabled by default and the field is Linux-only. This
case checks disk-backed emptyDir and does not infer Kubernetes defaults
for storage driver or provider volumes.

- [Kubernetes v1.37 emptyDir volume permissions](https://kubernetes.io/docs/tasks/configure-pod-container/configure-emptydir-volume-mode/)
- [kind v0.33.0 pinned v1.37 node image](https://github.com/kubernetes-sigs/kind/releases/tag/v0.33.0)
