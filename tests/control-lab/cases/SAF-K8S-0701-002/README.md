# SAF-K8S-0701-002 — CSI driver security

From the framework checkout, run the disposable single-node comparison.

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0701-002 --docker-context desktop-linux
```

From the lab checkout, invoke `python3 lab.py` with the same arguments.
The fixture uses the upstream Kubernetes v1.36.1 SIG Storage hostpath
demonstration, adapted for this filesystem-only test. Three upstream
container images are pinned by index digest. The reviewed Linux arm64
and amd64 image manifest digests appear in `pins.json`. The Pod spec
must use those exact index pins, and the live container status must
report the accepted index or appropriate platform manifest digest.

The standalone workload first proves its actual Kubernetes identity.
Its two named reads become authorized only after a narrow RoleBinding,
while the tested storage and snapshot authorization requests stay
denied. The native CSI fixture then compares the effective grants of
the running driver's actual shared ServiceAccount, provisions an
owned filesystem PVC, writes and reads one inert marker, and observes
reclamation of the exact case-owned PV. The dedicated CSI Node plugin
requires a privileged container and specific Kind-internal hostPath
mounts. The case checks for absence of user host binds before starting
it and leaves the project and host storage outside the profile. Only
the external provisioner receives the projected API token. Both CSI
functions share the upstream ServiceAccount. The exact-image admission
policy accepts the three pinned containers and refuses an otherwise
valid server dry-run with one altered reference. The probes stay
absent and the running driver's UID and images remain unchanged.

The fixture installs three upstream snapshot API definitions after
verifying the exact immutable commit, lengths, Git blob IDs and
SHA-256 digests. Two actual projected-token Pods send identical
server-dry-run requests for the owned bound claim. The scoped
snapshot-create role receives HTTP 201, and the ungranted identity
receives 403. The snapshot is absent afterward. Snapshot data-plane
creation, restore, raw block, attachment and expansion require
separate deployed evidence.

## Verify the adopted driver control

1. Inventory actual driver and sidecar versions, immutable image pins
   and trusted provenance, CSIDriver objects and installation authority.
   Verify the approved release and privilege profile against its
   supported storage and node platform. Compare admission of the
   allowed driver with a harmless server dry-run using an unapproved
   image or declared identity.
2. Verify effective controller, node and helper identities from
   running objects, including external roles, token mounts, scope of
   sidecars, hostPath and device needs, and approved exceptions.
   Compare required API operations with an unrelated operation and with
   each other role where the product supplies separate identities.
3. Use a disposable source PVC and authorized and unauthorized actors
   to verify the installed snapshot API and backing snapshot authority
   where supported. Verify actual source and destination boundaries,
   snapshot creation and restore, class and content access, and
   retained or deleted provider snapshots. Check where authenticated
   actor and immutable storage identity appear in audit results.
4. Compare governed StorageClass creation and read access for the
   storage admin, service identity, and ordinary workload. Retain
   API decisions, provider receipts where applicable, and independent
   readback of the exact case-owned volume operation.

[Kubernetes CSI hostpath fixture at v1.36.1](https://github.com/kubernetes/kubernetes/blob/v1.36.1/test/e2e/testing-manifests/storage-csi/hostpath/hostpath/csi-hostpath-plugin.yaml),
[SIG Storage hostpath test driver](https://github.com/kubernetes-csi/csi-driver-host-path/),
and [external provisioner RBAC at v6.1.1](https://github.com/kubernetes-csi/external-provisioner/blob/v6.1.1/deploy/kubernetes/rbac.yaml).

[External Snapshotter API definitions at the reviewed commit](https://github.com/kubernetes-csi/external-snapshotter/tree/a6a3d9d6b5f6f1e6fa0d311148b696556e4499e8/client/config/crd).
