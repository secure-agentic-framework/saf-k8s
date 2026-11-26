# Verify approved index recovery and staged migration on Kubernetes

    python3 tests/control-lab/lab.py test SAF-K8S-0909-006 --docker-context desktop-linux

The case stores inert vectors in SQLite. It compares behavior with and
without an approved snapshot check, runs a fixed reference query, and
rebuilds and retires one fixture generation.

The approved snapshot is copied to a second fixture PVC. The test deletes
the workload and replaces its primary claim, requiring both a new claim UID
and a different bound volume. The backup claim keeps its identity and exact
snapshot digest. The replacement workload restores that copy and observes
the approved digest, SQLite integrity and the expected query result.

For a deployment, record the actual engine, backed-up state and compatibility,
concurrent write behavior, independent storage failure domains, backup
retention or immutability, and measured recovery time and data loss. Verify
the governed retirement and sanitization requirements on the actual storage.
Both case volumes use the same disposable Kubernetes cluster.

## Approved migration

After the approved snapshot is restored, a separate
immutable ConfigMap supplies a fixed migration plan. The plan digest is pinned in the
case-owned SQLite helper and the API confirms the ConfigMap is immutable. The plan binds the
current synthetic model, three-dimensional corpus digest and dimension to a different
synthetic model, two-dimensional target corpus digest, fixed coordinate-projection transform,
and known query result.

An incompatible model/dimension request is refused before staging, and the helper compares the
exact active SQLite file digest before and after with the restored backup digest. For the
approved request, the helper reads the source, stages a new SQLite database on the same PVC,
checks SQLite integrity, target model, dimension, document count, target corpus digest and
known query while still staged, and only then atomically replaces the active file. It verifies
the active bytes match the validated staging bytes and repeats the target checks after
activation. Only the fixed case records and deterministic transform are used.

The case exercises local sequencing for a synthetic model and dimension migration. For the
adopted rollout, record model compatibility, embedding quality, concurrent writer coordination,
storage and engine compatibility, staged readback and rollback evidence. Verify sanitization
with the provider and storage owners.

## Named generation retirement

During migration the fixture keeps a named v1 generation on the primary PVC
and a copy on the backup PVC. It verifies the two fixture paths, validates
their SQLite contents, and unlinks them only after the v2 activation and
the preserved recovery snapshot pass their separate checks. Readback
confirms both targets are absent. The exact migrated file and the separate
approved recovery snapshot preserve their digests and known query results.

In the adopted storage system, independently inventory replicas, snapshots,
volumes and other retained copies. Verify the applicable approved disposal
procedure and protect designated recovery copies.
