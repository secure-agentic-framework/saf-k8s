# SAF-K8S-1005-030 — etcd recovery rehearsal

This case runs an ordinary snapshot and restoration rehearsal for a fresh,
single-control-plane Kind cluster running Kubernetes v1.36.1. The node image is
pinned to the digest published for the lab's Kind release, and the offline
`etcdutl` helper image is pinned by digest. There are no workload images.

The only user-level record is a case-owned ConfigMap in
`saf-1005-030-rehearsal`. Its `state` value changes from a reserved synthetic
baseline to a reserved post-backup marker. The case snapshots the live etcd
member, checks the snapshot with `etcdutl`, and keeps its bytes in a private
temporary directory. It creates a truncated copy to exercise a concrete reject
path. A failed run-local digest comparison or native snapshot inspection aborts
before restoration; the case verifies through the API that the ConfigMap is
still unchanged. It then uses the intact verified snapshot, requests an etcd
revision bump and compaction, stops the kubeadm static control-plane
containers, points the disposable etcd manifest at a new data directory, and
restarts the control plane. Success requires the original ConfigMap state and
UID to return through the Kubernetes API and the node to become `Ready`.

The run-local SHA-256 value is useful for detecting accidental alteration
between snapshot and restore in this rehearsal. It is not an independently
trusted production digest, signature, or provenance record. If the reject check
fails, restoration is not attempted. If the later control-plane restart does
not return the API and sentinel, the code restores the original static etcd
manifest reference, restarts kubelet, aborts the case, and leaves the runner to
remove the disposable cluster. The original etcd data directory is preserved
throughout as that local abort path.

## Rehearsal procedure

1. Confirm the runner created only its own single-node Kind v1.36.1 cluster and
   that the API exposes the expected kubeadm etcd Pod and data-directory
   mount. Abort if the profile differs.
2. Create the labeled ConfigMap from `fixtures/rehearsal.json`. Read it through
   the API and retain only its synthetic `state`, UID, name, and namespace as
   the expected baseline.
3. Save a live-member snapshot with the etcd client TLS files, copy the opaque
   snapshot into a private temporary directory and set the file mode to `0600`, record its run-local
   SHA-256, and require `etcdutl snapshot status` to accept it.
4. Truncate a copy. Require both the digest comparison and native status
   inspection to reject it. Do not call restore. Read the sentinel through the
   API and confirm its state and UID still match the baseline. A failure at
   this point is an abort; retain no bad artifact and continue only with the
   intact snapshot.
5. Change the same sentinel to the post-backup marker and verify that state
   through the API. Restore the intact snapshot to a new data directory with
   revision bump and compaction requested.
6. Stop kubelet and the disposable node's static API server, etcd,
   controller-manager, and scheduler containers. Change only the etcd
   manifest's host path to the new restore directory, then restart kubelet.
7. Wait for the API to return. Require the ConfigMap baseline and original UID
   to reappear, require the control-plane node and API to become Ready, and
   verify the list revision reflects the requested bump. Make a
   second API read and compare it with the first restoration observation.
8. If restore or startup fails, stop kubelet, put the saved etcd manifest back
   on the original `/var/lib/etcd` directory, restart kubelet, abort the case,
   and let the harness delete the disposable cluster. The original data
   directory is preserved until cluster deletion.

## Expected observations

- **Red:** the deliberately truncated backup fails both the run-local digest
  comparison and native snapshot inspection; no restore is attempted and the
  API still returns the unchanged baseline ConfigMap.
- **Green:** after changing that ConfigMap, the intact backup is restored into
  a new data directory. Kubernetes API readback returns the earlier value and
  same object UID, and the control-plane node becomes Ready.
- **Positive:** a second API read returns the same restored object state after
  node readiness. Evidence contains only synthetic metadata, an opaque snapshot
  digest, and API status/UID fields.

`etcd-recovery-observations.raw.json` is the case's raw observation file. The
snapshot itself is never copied to evidence. The code never reads or exports
Kubernetes Secret objects, snapshot keys, snapshot values, or credentials. The
etcd backup necessarily contains the disposable cluster's full etcd database;
no production data is present or used. The case contacts no feeds or external
targets. Recovery helper containers use `--network=none`.

## Control coverage and limits

| Control obligation | Evidence in this case |
| --- | --- |
| Document and rehearse etcd restoration | README sequence plus an executed snapshot, rejection, restore, restart, and API readback path |
| Successful execution record | The runner records rejection, restoration, and subsequent API observations in its result |
| Critical Kubernetes control-plane path | One single-node kubeadm static-etcd Kind control plane and one API-observable synthetic ConfigMap |
| Production recovery readiness | Unverified: no production cluster, credentials, backup system, custody, encryption, or incident path is exercised |
| Broader restoration | Unverified: no multi-member/external etcd, control-plane rebuild, workload recovery, persistent volumes, service traffic, RPO/RTO, or business-priority sequencing |

The readback proves restoration of one API object in this disposable profile.
It does not prove a production backup is complete, authentic, encrypted, recent,
available under incident conditions, or authorized for use. The kubeadm
`kubeadm-config` ConfigMap's `etcd.local.dataDir` is not modified: this cluster
is deleted by the lab runner immediately after the case, and durable cluster
reconfiguration is outside this exercise. A production runbook must update
that setting along with the static Pod manifest when the new data directory is
to persist across kubeadm upgrades.

Run through the supervisor's harness after review:

```sh
python3 lab.py test SAF-K8S-1005-030 --docker-context desktop-linux
```

## Official primary sources

- [Kubernetes v1.36: Operating etcd clusters](https://v1-36.docs.kubernetes.io/docs/tasks/administer-cluster/configure-upgrade-etcd/) — live snapshot creation, `etcdutl` inspection, stopping API servers before restore, changing the static Pod host path, restarting kubelet, and updating `kubeadm-config` for durable use.
- [etcd v3.6 disaster recovery](https://etcd.io/docs/v3.6/op-guide/recovery/) — snapshot restoration, new data directories, and revision bump/compaction for Kubernetes watch caches.
- [Kubernetes etcd image metadata](https://github.com/kubernetes/k8s.io/blob/main/registry.k8s.io/images/k8s-staging-etcd/images.yaml) — official staged etcd image digest mapping used for the offline recovery helper.
- [Kind v0.32.0 release](https://github.com/kubernetes-sigs/kind/releases/tag/v0.32.0) — Kubernetes v1.36.1 node image used by the runner.
- [Kind quick start](https://kind.sigs.k8s.io/docs/user/quick-start/) — selecting an explicit node image and disposable cluster lifecycle.

## Adopter verification

1. Reconcile the deployed control-plane topology and documented runbook with the official version-specific kubeadm/etcd procedure. Identify etcd membership, snapshot destination, custody, encryption, kubeadm configuration persistence, and authorized operators.
2. In isolated staging with representative topology, verify backup provenance, snapshot status, and restore readiness before any restart. Use a synthetic sentinel and a separate corrupted-copy rejection that aborts before restoration.
3. Rehearse recovery under approved change control. Confirm all required members and API paths return, sentinel state and identity are correct, and dependent services meet organization-defined recovery objectives. Verify static manifest and kubeadm configuration remain consistent after restart/upgrades.
4. Retain runbook version, operators/approvals, topology, backup verification, timeline, service checks, data integrity results, and follow-up actions. Keep snapshot bytes and credentials out of ordinary evidence.
