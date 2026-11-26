# Verify approved index recovery from a retained Kubernetes volume

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
