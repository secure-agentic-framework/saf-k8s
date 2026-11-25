# SAF-K8S-0601-010 deployment-aware artifact retention

The case uses a private temporary registry and storage on an owned
Kind cluster. It deploys an immutable BusyBox digest and tests a cleanup
rule against live Deployment state, retention periods by artifact type,
and a hold. A fixture chart and a held model stay available. The expired
model is deleted and its unreferenced content goes through the registry's
garbage collector with the registry stopped.

The case uses fixed release dates. It requires local Helm and uses pinned
registry, Skopeo and BusyBox images. Production cleanup needs
additional coverage of deployment references, replication, artifact
relationships and lifecycle operations.

[CNCF Distribution garbage collection](https://distribution.github.io/distribution/about/garbage-collection/)

## Adopter verification

1. Inventory every deployed registry/model store and artifact type, recording immutable digests referenced by running and rollback releases.
2. Verify each artifact-type retention window, holds and renewals, plus the relationships between manifests, tags, shared blobs, signatures and attestations.
3. Review scheduled cleanup/garbage collection and prove it preserves live, rollback and held references while removing only expired unreferenced artifacts. Use an approved nonproduction test where destructive cleanup behavior must be demonstrated.
4. Test retrieval or restoration from each replica/backup path and retain the operation log, audit event and recovery timing.
