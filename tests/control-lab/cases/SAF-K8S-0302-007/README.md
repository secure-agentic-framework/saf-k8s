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

The harness's top-level `node_image` and `kubernetes` evidence fields describe
the base v1.36.1 cluster only. The base case remains intact. Each additional
v1.37.0 profile records its server and kubelet versions, pinned kind node
image, and configured feature-gate values in the profile’s version assertion. Use kind v0.33.0 or compatible for these profiles.

The existing mixed-gate profile keeps `EmptyDirVolumeMode=true` on the API
server and control-plane kubelet, with the worker kubelet gate set to `false`.
It verifies that the API retains an explicit `0700` field while that worker
mounts the disk-backed `emptyDir` at `0777` and allows a nonroot write. On the
enabled kubelet it compares the mounted mode and a nonroot write decision, and
records the `fsGroup` interaction separately.

The added API-off profile sets the v1.37.0 API-server gate to `false` and both
kubelet gates to `true`. It submits the same harmless `0700` `emptyDir` Pod
fixture used for the mixed-gate skew probe, separately reads the stored Pod,
and checks that `mode` is absent there. It then checks the actual Linux mount
mode and a harmless write with the same nonroot UID 65534 used by the other profiles. This exercises API-server field
pruning separately from kubelet behavior with a retained field.

These profiles check only disposable kind Linux nodes and disk-backed
`emptyDir`. They do not establish behavior for Windows, CSI or other provider
volumes, production cluster gate configuration, or workloads with other
permission modifiers. The feature is alpha and disabled by default in v1.37;
the gate must be enabled on all relevant components for the mode field to be
enforced. KEP-5502 describes API-side field dropping when the gate is disabled,
the kubelet's legacy `0777` behavior, and both sides of version skew.

- [Kubernetes v1.37 emptyDir volume permissions](https://v1-37.docs.kubernetes.io/docs/tasks/configure-pod-container/configure-emptydir-volume-mode/)
- [Kubernetes v1.37 feature-gate registry](https://github.com/kubernetes/kubernetes/blob/v1.37.0/pkg/features/kube_features.go)
- [Kubernetes v1.37 API field handling](https://github.com/kubernetes/kubernetes/blob/v1.37.0/pkg/api/pod/util.go)
- [Kubernetes v1.37 emptyDir kubelet implementation](https://github.com/kubernetes/kubernetes/blob/v1.37.0/pkg/volume/emptydir/empty_dir.go)
- [KEP-5502: EmptyDir Volume Permission Mode](https://github.com/kubernetes/enhancements/blob/master/keps/sig-storage/5502-emptydir-volume-mode/README.md)
- [kind v0.33.0 pinned v1.37 node image](https://github.com/kubernetes-sigs/kind/releases/tag/v0.33.0)

## Verify group isolation on an adopter's storage

The base test includes an approved comparison identity. It writes to a
separate local claim and gets a permission error writing to an explicitly
mounted synthetic comparison volume. The expected group owns that volume,
and the approved peer reads back the unchanged marker. The comparison Pod
uses supplementary groups without fsGroup so its mount preserves ownership.

1. Inventory each workload's approved numeric groups and volume and mount
   scope. Identify which paths are shared and who owns each storage class,
   volume driver, and access configuration. Review namespace authorization
   and how the admission criteria bind to approved workload identities.
2. Observe effective process groups with `id` and mounted UID, GID and
   permission bits with `stat`. Determine whether the kubelet or CSI driver
   handles volume ownership. Test positive and denied writes to synthetic
   objects in an equivalent profile and retain evidence that the protected
   marker stayed unchanged.
3. For v1.37 emptyDir mode, compare the API response and stored Pod with
   mounted permission bits on every eligible node profile. Record the API
   and kubelet version and gate settings, fsGroup, and the actual write
   result. Cover mixed-node state during an upgrade.
4. Retain evidence per storage driver, filesystem, scope and identity.
   A mount, declared security context, or PVC access mode alone leaves the
   effective process and storage permissions unverified.
