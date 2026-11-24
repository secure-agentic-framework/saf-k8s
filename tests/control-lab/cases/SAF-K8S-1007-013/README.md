# SAF-K8S-1007-013 — AI infrastructure asset inventory

Run from the SAF-K8S framework root on a disposable Kind cluster.

```sh
python3 tests/control-lab/lab.py test SAF-K8S-1007-013 --docker-context desktop-linux
```

The owned fixture performs native Kubernetes LIST and WATCH operations and
publishes per-source identity, cursor, capture time, coverage and freshness.
Separate Kubernetes subjects read sources and publish the inventory. The
reader cannot create or patch the snapshot. The publisher may update the
named record and is denied source enumeration or unrelated updates.

| Source | Verified behavior |
| --- | --- |
| ConfigMaps, Services, PVCs, and Jobs | Watch events and relists reconcile changes and removals. A denied Job LIST produces unknown or stale status, preserves the last successful state, and clears after access is restored. |
| Model registry | A pinned OCI registry serves two synthetic model revisions. The collector verifies returned manifest and blob digests and publishes the version change. |
| DRA ResourceClaim | Kubernetes schedules a claim against an owned synthetic ResourceSlice. The reader verifies the exact assigned device tuple and reservation for the owned Pod, then reconciles an update and removal. |
| Dataset catalog | An isolated HTTP service serves two versions of an inert dataset manifest. The reader validates the response ETag and content digest, then publishes the updated version and change history. |

The runner uses a fixture clock for reproducible freshness transitions. It
retains the source records for direct comparison with the published snapshot.
The accelerator case verifies native scheduling metadata for a synthetic
device. Driver preparation and physical device use require hardware evidence.
The dataset source serves metadata only.

## Verify your implementation

1. Inventory the applicable model, dataset, pipeline, endpoint and device
   allocation sources. Record the scope and owner of each authoritative
   source. Match active endpoint records and routes, data identifiers and
   digests, and device assignment or runtime evidence to the workload and
   capture time.
2. Exercise source changes and deletions with independently scoped read and
   publish access. Review last-good retention, unknown and stale alerts,
   recovery after watch expiration or relist, and the removal of deleted
   assets. Compare the visible inventory against expected coverage.
3. Check numeric freshness limits and cursor semantics per source. Validate
   registry authentication and versions, dataset metadata and lineage, and
   device assignment evidence on the adopter's applicable systems. Retain
   the source records, snapshot revisions and gap or alert evidence.

- [Kubernetes v1.36 API concepts](https://v1-36.docs.kubernetes.io/docs/reference/using-api/api-concepts/)
- [Kubernetes v1.36 RBAC](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/)
- [Kubernetes v1.36 Dynamic Resource Allocation](https://v1-36.docs.kubernetes.io/docs/concepts/scheduling-eviction/dynamic-resource-allocation/)
- [OCI Distribution Specification v1.1.1](https://github.com/opencontainers/distribution-spec/blob/v1.1.1/spec.md)
