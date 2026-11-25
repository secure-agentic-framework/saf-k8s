# SAF-K8S-1005-029 — Kubernetes backup verification

This draft exercises a disposable Kind v1.36.1 cluster. It checks an actual
snapshot made from that cluster's etcd keyspace and a file-level backup of an
inert marker on a PVC. The marker is reserved-placeholder text, not model or
training data. The etcd snapshot remains inside the disposable etcd container;
it is not copied into the evidence directory because a Kubernetes etcd snapshot
can contain cluster state. Evidence records snapshot status, integrity failures,
and the exact synthetic marker read from a separately restored etcd member.

The workload fixture writes the exact marker bytes to a PVC, creates a tar
backup on that PVC, and checks a valid archive, a bit-corrupted archive, and an
incomplete archive. A separate reader Pod observes restored bytes and reports
the byte count and SHA-256. This is a basic file-level fixture, not a CSI
VolumeSnapshot or independent off-cluster backup service.

## Expected observations

- **Red:** etcd snapshot status rejects an absent incomplete input; workload
  verification rejects a byte-corrupted archive and an incomplete archive.
- **Green:** `etcdutl snapshot status` accepts the complete snapshot and
  `etcdutl snapshot restore` restores it into an isolated data directory; the
  workload verifier accepts the complete marker archive.
- **Positive:** querying the restored etcd member returns the exact marker
  bytes, and a separate Pod reads byte-identical marker contents from the
  workload restore path. Evidence includes the marker digest and byte count,
  never the etcd snapshot or any Kubernetes object dump.

The etcd commands use the control-plane's own etcd container and certificates.
The restored member listens only on loopback inside that container. All scratch
files and the isolated restore process are deleted on successful case cleanup.
The case runner creates and deletes the disposable cluster; no existing cluster
is selected. The image references in the fixtures and case are digest-pinned.

## Coverage and limits

This case demonstrates offline etcd snapshot format/status checks, restoration
of one synthetic key in the same disposable cluster's isolated etcd process,
and integrity/readback for one ordinary PVC file archive. It does not verify
production backup schedules, copy isolation, immutability, encryption, key
custody, retention, cross-version restores, quorum recovery, an independent
control plane, CSI snapshot controllers or providers, model registries,
artifact stores, training checkpoints, large files, or recovery objectives.
The Kind local-path storage behavior is not evidence about any production
storage provider. The control's production claim therefore remains only
partially covered by this exercise.

The source documentation supports etcd snapshot/status/restore operations and
Kubernetes persistent-volume semantics. It does not mandate a particular
backup verification interval, required artifact inventory, or the archive
format used here; those remain organization-specific controls.

Primary sources:

- [Kubernetes v1.36 — Operating etcd clusters](https://v1-36.docs.kubernetes.io/docs/tasks/administer-cluster/configure-upgrade-etcd/)
- [etcd v3.6 — Disaster recovery](https://etcd.io/docs/v3.6/op-guide/recovery/)
- [Kubernetes v1.36 — Persistent Volumes](https://v1-36.docs.kubernetes.io/docs/concepts/storage/persistent-volumes/)

## Adopter verification

1. Inventory etcd, persistent volumes, model/artifact registries, training checkpoints, and all backup schedules, destinations, encryption keys, retention, and restore owners.
2. Verify backup jobs produce independently protected copies and that integrity/status checks run before restore. Reconcile the expected protected-source inventory against actual successful backup receipts.
3. In an isolated recovery environment, restore representative etcd and volume/application artifacts from the backup destination, compare synthetic sentinel state and digests, and verify an incomplete/corrupt copy is rejected. Measure the approved RPO/RTO without touching production state.
4. Retain source coverage, backup and restore receipts, key/custody controls, provider/CSI evidence, and gap owners. Do not export raw etcd snapshots or credentials into evidence.
